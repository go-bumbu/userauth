package sessionauth

import (
	"encoding/gob"
	"fmt"
	"github.com/gorilla/sessions"
	"net/http"
	"time"
)

func init() {
	// this is needed so that cookiestore can manage the session data
	gob.Register(SessionData{})
}

type Cfg struct {
	// concrete store to handle the sessions at the backend, needs to implement the gorilla session store interface
	Store sessions.Store
	// rolling window session duration, will be renewed on subsequent requests,
	// e.g. if set to 24h, and you log in once a day, it will only expire at max MaxSessionDur
	// default is set to 1h
	SessionDur time.Duration
	// force a new login after this period, e.g. every 30 days, default is 24h
	MaxSessionDur time.Duration

	// time between the last session update, used to not overload the session store
	MinWriteSpace time.Duration
}

type AuthMngr struct {
	store sessions.Store

	sessionDur    time.Duration
	minWriteSpace time.Duration
	maxSessionDur time.Duration
}

func NewAuthMngr(cfg Cfg) (*AuthMngr, error) {

	if cfg.SessionDur == 0 {
		cfg.SessionDur = time.Hour * 1
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

	c := AuthMngr{
		sessionDur:    cfg.SessionDur,
		minWriteSpace: cfg.MinWriteSpace,
		maxSessionDur: cfg.MaxSessionDur,
		store:         cfg.Store,
	}
	return &c, nil
}

const (
	SessionName    = "_c_auth"
	sessionDataKey = "data"
)

// Login is a convenience function to write a new logged-in session for a specific user id and write it
func (auth *AuthMngr) Login(r *http.Request, w http.ResponseWriter, user string) error {
	authData := SessionData{
		UserData: UserData{
			UserId:          user,
			IsAuthenticated: true,
		},
		Expiration:  time.Now().Add(auth.sessionDur),
		ForceReAuth: time.Now().Add(auth.maxSessionDur),
	}
	session, err := auth.store.Get(r, SessionName)
	if err != nil {
		return err
	}
	return auth.write(r, w, session, authData)
}

// Logout is a convenience function to logout the current user
func (auth *AuthMngr) Logout(r *http.Request, w http.ResponseWriter) error {
	authData := SessionData{
		UserData: UserData{
			IsAuthenticated: false,
		},
	}
	session, err := auth.store.Get(r, SessionName)
	if err != nil {
		return err
	}
	return auth.write(r, w, session, authData)
}

// the Write public function is commented out for now, until it might be needed to not blow the API
// Use Login() instead
//func (auth *AuthMngr) Write(r *http.Request, w http.ResponseWriter, data SessionData) ( error) {
//	session, err := auth.store.Get(r, SessionName)
//	if err != nil {
//		return err
//	}
//	return auth.write(r, w, session, data)
//}

// write is responsible for writing the login session data into the backend session
// it implements a throttling mechanism ...
// TODO e.g. logout will not work with throtling,
func (auth *AuthMngr) write(r *http.Request, w http.ResponseWriter, session *sessions.Session, data SessionData) error {
	now := time.Now()
	if data.LastUpdate.Add(auth.minWriteSpace).After(now) {
		return nil
	}
	data.LastUpdate = now

	session.Values[sessionDataKey] = data
	err := session.Save(r, w)
	if err != nil {
		return err
	}
	return nil
}

func (auth *AuthMngr) Read(r *http.Request) (SessionData, error) {
	data, _, err := auth.read(r)
	return data, err
}
func (auth *AuthMngr) read(r *http.Request) (SessionData, *sessions.Session, error) {
	session, err := auth.store.Get(r, SessionName)
	if err != nil {
		// TODO find better solution to handle sessions when the FS store is gone but the client still has a session
		return SessionData{}, nil, err
	}

	key := session.Values[sessionDataKey]
	if key == nil {
		return SessionData{}, nil, err
	}
	authData := key.(SessionData)
	authData.Process(auth.sessionDur)
	return authData, session, err
}

// ReadUpdate is used to read the session, and update the session expiry timestamp
// it only extends the session if enough time has passed since the last write to not overload
// the session store on many requests.
// it returns the session data if the user is logged in
func (auth *AuthMngr) ReadUpdate(r *http.Request, w http.ResponseWriter) (SessionData, error) {
	data, session, err := auth.read(r)
	if err != nil {
		return SessionData{}, err
	}

	if data.IsAuthenticated {
		err = auth.write(r, w, session, data)
		if err != nil {
			return SessionData{}, err
		}
		return data, nil
	}
	return SessionData{}, nil
}

// Session Data  ------------------------------------------------------------

type UserData struct {
	UserId          string // ID or username
	DeviceID        string // hold information about the device
	IsAuthenticated bool
}
type SessionData struct {
	UserData

	// expiration of the session, e.g. 2 days, after a login is required, this value can be updated by "keep me logged in"
	Expiration time.Time
	// force re-auth, max time a session is valid, even if keep logged in is in place.
	ForceReAuth time.Time
	LastUpdate  time.Time
}

func (d *SessionData) Process(extend time.Duration) {
	// check expiration
	if d.Expiration.Before(time.Now()) {
		d.IsAuthenticated = false
	}
	// check hard expiration
	if d.ForceReAuth.Before(time.Now()) {
		d.IsAuthenticated = false
	}
	// extend normal expiration
	if d.IsAuthenticated && extend > 0 {
		d.Expiration = d.Expiration.Add(extend)
	}
}