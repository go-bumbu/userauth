package sessionauth

import (
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/gorilla/securecookie"
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
	AllowRenew bool
	// force a new login after this period, e.g. every 30 days, default is 24h
	MaxSessionDur time.Duration

	// time between the last session update, used to not overload the session store
	MinWriteSpace time.Duration
}

type Manager struct {
	store sessions.Store

	sessionDur    time.Duration
	allowRenew    bool
	minWriteSpace time.Duration
	maxSessionDur time.Duration
}

func New(cfg Cfg) (*Manager, error) {

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

	c := Manager{
		sessionDur:    cfg.SessionDur,
		allowRenew:    cfg.AllowRenew,
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

// LoginUser will store the user as logged-in in the session store
// it is not explicitly needed to verify the authentication, but used in handlers that log in a user
// and initiate a session, e.g. see JsonAuthHandler
func (sMngr *Manager) LoginUser(r *http.Request, w http.ResponseWriter, userId string, sessionRenew bool) error {

	if !sMngr.allowRenew {
		// force session renew to false if not allowed
		sessionRenew = false
	}
	authData := SessionData{
		UserData: UserData{
			UserId:          userId,
			IsAuthenticated: true,
		},
		RenewExpiration: sessionRenew,
		Expiration:      time.Now().Add(sMngr.sessionDur),
		ForceReAuth:     time.Now().Add(sMngr.maxSessionDur),
	}
	//session, err := sMngr.store.Get(r, SessionName)
	session, err := sMngr.Get(r, SessionName)
	if err != nil {
		return err
	}
	return sMngr.write(r, w, session, authData)
}

// Get is a wrapper around session get that will ignore cookie error and return a new session
func (sMngr *Manager) Get(r *http.Request, name string) (*sessions.Session, error) {
	session, err := sMngr.store.Get(r, name)
	if err != nil {
		var multiErr securecookie.MultiError
		if errors.As(err, &multiErr) {
			for _, singleErr := range multiErr {
				// ignoring existing cookie, e.g. because we generated new key pairs
				// then we return a new empty session
				if singleErr.Error() == "securecookie: the value is not valid" {
					return session, nil
				}
			}
		}
		return nil, err
	}
	return session, nil
}

// LogoutUser is a convenience function to log out the current user based on the session information
// note that if the same user has multiple sessions this will not log out the other sessions
func (sMngr *Manager) LogoutUser(r *http.Request, w http.ResponseWriter) error {
	authData := SessionData{
		UserData: UserData{
			IsAuthenticated: false,
		},
	}
	session, err := sMngr.Get(r, SessionName)
	if err != nil {
		return err
	}
	return sMngr.write(r, w, session, authData)
}

//// ReadUpdate is used to read the session, and update the session expiry timestamp
//// it only extends the session if enough time has passed since the last write to not overload
//// the session store on many requests.
//// it returns the session data if the user is logged in
//func (sMngr *Manager) ReadUpdate(r *http.Request, w http.ResponseWriter) (SessionData, error) {
//	data, session, err := sMngr.read(r)
//	if err != nil {
//		return SessionData{}, err
//	}
//
//	if data.IsAuthenticated {
//		err = sMngr.write(r, w, session, data)
//		if err != nil {
//			return SessionData{}, err
//		}
//		return data, nil
//	}
//	return SessionData{}, nil
//}

//// UpdateExpiry will write into the session updating the expiry time of the session
//// this method contains a throttling mechanism in order to only write session updates after a certain period of time
//// to avoid overloading the sessions store
//func (sMngr *Manager) UpdateExpiry(r *http.Request, w http.ResponseWriter) error {
//	data, session, err := sMngr.read(r)
//	if err != nil {
//		return err
//	}
//	return sMngr.updateExpiry(data, session, r, w)
//}

func (sMngr *Manager) updateExpiry(data SessionData, session *sessions.Session, r *http.Request, w http.ResponseWriter) error {
	if data.LastUpdate.Add(sMngr.minWriteSpace).After(time.Now()) {
		return nil
	}
	if data.RenewExpiration {
		data.Expiration = time.Now().Add(sMngr.sessionDur)
	}
	return sMngr.write(r, w, session, data)
}

// write is responsible for writing the login session data into the backend session
// write is kept intentionally private for now.
func (sMngr *Manager) write(r *http.Request, w http.ResponseWriter, session *sessions.Session, data SessionData) error {
	data.LastUpdate = time.Now()
	session.Values[sessionDataKey] = data
	err := session.Save(r, w)
	if err != nil {
		return err
	}
	return nil
}

// GetSessData gets the user information out of the session store
func (sMngr *Manager) GetSessData(r *http.Request) (SessionData, error) {
	data, _, err := sMngr.read(r)
	return data, err
}

func (sMngr *Manager) read(r *http.Request) (SessionData, *sessions.Session, error) {
	session, err := sMngr.Get(r, SessionName)
	if err != nil {
		return SessionData{}, nil, err
	}

	key := session.Values[sessionDataKey]
	if key == nil {
		return SessionData{}, nil, err
	}
	authData := key.(SessionData)
	authData.Verify()
	return authData, session, err
}

// Session Value  ------------------------------------------------------------

type UserData struct {
	UserId          string // Key or username
	DeviceID        string // hold information about the device
	IsAuthenticated bool
}
type SessionData struct {
	UserData

	// expiration of the session, e.g. 2 days, after a login is required, this value can be updated by "keep me logged in"
	Expiration      time.Time
	RenewExpiration bool
	// force re-auth, max time a session is valid, even if keep logged in is in place.
	ForceReAuth time.Time
	LastUpdate  time.Time
}

func (d *SessionData) Verify() {
	// check expiration
	if d.Expiration.Before(time.Now()) {
		d.IsAuthenticated = false
	}
	// check hard expiration
	if d.ForceReAuth.Before(time.Now()) {
		d.IsAuthenticated = false
	}
	// extend normal expiration
	//if d.IsAuthenticated && extend > 0 {
	//	d.Expiration = d.Expiration.Add(extend)
	//}
}
