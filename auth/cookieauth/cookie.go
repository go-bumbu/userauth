package cookieauth

import (
	"encoding/gob"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/auth/chain"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

func init() {
	gob.Register(SessionData{})
}

// Cfg configures the session manager.
type Cfg struct {
	// Store handles sessions at the backend (e.g. cookie or filesystem).
	Store sessions.Store
	// SessionDur is the rolling window session duration, renewed on subsequent requests.
	// Default is 1h.
	SessionDur time.Duration
	AllowRenew bool
	// MaxSessionDur forces re-login after this period. Default is 24h.
	MaxSessionDur time.Duration
	// MinWriteSpace is the minimum time between session store writes.
	MinWriteSpace time.Duration
	// CookieName is the session cookie name. Defaults to DefaultCookieName.
	CookieName string
	Logger     *slog.Logger
}

// Manager manages session storage and validation. It implements chain.AuthHandler.
type Manager struct {
	store         sessions.Store
	sessionDur    time.Duration
	allowRenew    bool
	minWriteSpace time.Duration
	maxSessionDur time.Duration
	cookieName    string
	logger        *slog.Logger
}

const (
	DefaultCookieName = "_c_auth"
	sessionDataKey    = "data"
	SessionMngrName   = "sessionAuth"
)

// New creates a new session Manager.
func New(cfg Cfg) (*Manager, error) {
	if cfg.SessionDur == 0 {
		cfg.SessionDur = time.Hour
	}
	if cfg.MaxSessionDur == 0 {
		cfg.MaxSessionDur = time.Hour * 24
	}
	if cfg.MinWriteSpace == 0 {
		cfg.MinWriteSpace = time.Minute * 2
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("session store cannot be nil")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
	}

	m := Manager{
		sessionDur:    cfg.SessionDur,
		allowRenew:    cfg.AllowRenew,
		minWriteSpace: cfg.MinWriteSpace,
		maxSessionDur: cfg.MaxSessionDur,
		cookieName:    cfg.CookieName,
		store:         cfg.Store,
		logger:        cfg.Logger.With("auth-handler", SessionMngrName),
	}
	return &m, nil
}

// Name implements chain.AuthHandler.
func (m *Manager) Name() string {
	return SessionMngrName
}

// HandleAuth implements chain.AuthHandler. It validates whether the request has a valid session.
func (m *Manager) HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool) {
	data, session, err := m.read(r)
	if err != nil {
		m.logger.Debug("session auth: error reading session", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false, false
	}
	if data.IsAuthenticated {
		m.logger.Debug("session auth: user authenticated", "user", data.UserId)
		CtxSetUserData(r, data)
		err = m.updateExpiry(data, session, r, w)
		if err != nil {
			m.logger.Debug("session auth: error updating session expiry", "user", data.UserId, "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false, false
		}
		return true, false
	}
	m.logger.Debug("session auth: user not authenticated",
		"user", data.UserId,
		"expiration", data.Expiration,
		"forceReAuth", data.ForceReAuth,
	)
	return false, false
}

// Middleware returns a session-only middleware that allows access when the user has a valid session.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := m.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// Verify chain.AuthHandler at compile time.
var _ chain.AuthHandler = (*Manager)(nil)

// LoginUser stores the user as logged-in in the session store.
func (m *Manager) LoginUser(r *http.Request, w http.ResponseWriter, userID string, sessionRenew bool) error {
	if !m.allowRenew {
		sessionRenew = false
	}
	authData := SessionData{
		UserData: UserData{
			UserId:          userID,
			IsAuthenticated: true,
		},
		RenewExpiration: sessionRenew,
		Expiration:      time.Now().Add(m.sessionDur),
		ForceReAuth:     time.Now().Add(m.maxSessionDur),
	}
	session, err := m.Get(r, m.cookieName)
	if err != nil {
		m.logger.Debug("login user: error getting session", "user", userID, "error", err)
		return err
	}
	m.logger.Debug("login user: creating session",
		"user", userID,
		"sessionDur", m.sessionDur,
		"maxSessionDur", m.maxSessionDur,
		"renewExpiration", sessionRenew,
	)
	return m.write(r, w, session, authData)
}

// Get returns the session from the store, or a new session on cookie decode errors.
func (m *Manager) Get(r *http.Request, name string) (*sessions.Session, error) {
	session, err := m.store.Get(r, name)
	if err != nil {
		var multiErr securecookie.MultiError
		if errors.As(err, &multiErr) {
			// securecookie wraps all decode failures (bad MAC, expired,
			// gob type mismatch, etc.) as MultiError. The underlying
			// store always returns a fresh session alongside the error,
			// so it is safe to discard the error and use the empty session.
			return session, nil
		}
		return nil, err
	}
	return session, nil
}

// LogoutUser clears the session.
func (m *Manager) LogoutUser(r *http.Request, w http.ResponseWriter) error {
	authData := SessionData{
		UserData: UserData{IsAuthenticated: false},
	}
	session, err := m.Get(r, m.cookieName)
	if err != nil {
		return err
	}
	return m.write(r, w, session, authData)
}

// TouchSession renews the rolling session expiry if the session is authenticated and enough
// time has passed since the last write (MinWriteSpace). Use this in custom handlers that
// don't use HandleAuth/Middleware but still need session renewal.
func (m *Manager) TouchSession(r *http.Request, w http.ResponseWriter) error {
	data, session, err := m.read(r)
	if err != nil || !data.IsAuthenticated {
		return err
	}
	return m.updateExpiry(data, session, r, w)
}

func (m *Manager) updateExpiry(data SessionData, session *sessions.Session, r *http.Request, w http.ResponseWriter) error {
	if data.LastUpdate.Add(m.minWriteSpace).After(time.Now()) {
		return nil
	}
	if data.RenewExpiration {
		data.Expiration = time.Now().Add(m.sessionDur)
	}
	return m.write(r, w, session, data)
}

func (m *Manager) write(r *http.Request, w http.ResponseWriter, session *sessions.Session, data SessionData) error {
	data.LastUpdate = time.Now()
	session.Values[sessionDataKey] = data
	return session.Save(r, w)
}

// GetSessData returns session data from the request.
func (m *Manager) GetSessData(r *http.Request) (SessionData, error) {
	data, _, err := m.read(r)
	return data, err
}

func (m *Manager) read(r *http.Request) (SessionData, *sessions.Session, error) {
	session, err := m.Get(r, m.cookieName)
	if err != nil {
		// Cookie is corrupt or contains types from an old build;
		// treat it as "no session" rather than returning a 500.
		m.logger.Debug("session read: discarding undecodable cookie", "cookie", m.cookieName, "error", err)
		if session == nil {
			return SessionData{}, nil, nil
		}
		session.Values = nil
		return SessionData{}, session, nil
	}
	key := session.Values[sessionDataKey]
	if key == nil {
		m.logger.Debug("session read: no session data found in store", "cookie", m.cookieName, "isNew", session.IsNew)
		return SessionData{}, session, nil
	}
	authData := key.(SessionData)
	preVerify := authData.IsAuthenticated
	authData.Verify()
	if preVerify && !authData.IsAuthenticated {
		m.logger.Debug("session read: session expired after verify",
			"user", authData.UserId,
			"expiration", authData.Expiration,
			"forceReAuth", authData.ForceReAuth,
		)
	}
	return authData, session, nil
}

// UserData holds identity and auth state for the current request.
type UserData struct {
	UserId          string
	DeviceID        string
	IsAuthenticated bool
}

// SessionData is the value stored in the session.
type SessionData struct {
	UserData
	Expiration      time.Time
	RenewExpiration bool
	ForceReAuth     time.Time
	LastUpdate      time.Time
}

// Verify updates IsAuthenticated based on expiration and force-reauth times.
func (d *SessionData) Verify() {
	if d.Expiration.Before(time.Now()) {
		d.IsAuthenticated = false
	}
	if d.ForceReAuth.Before(time.Now()) {
		d.IsAuthenticated = false
	}
}
