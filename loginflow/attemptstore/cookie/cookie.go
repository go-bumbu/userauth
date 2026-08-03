// Package cookie provides a cookie-based loginflow.AttemptStore. The attempt
// travels in a signed and encrypted cookie (gorilla/securecookie), so no
// server-side state is required — suitable for multi-instance deployments
// that share the same keys.
package cookie

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/loginflow"
	"github.com/gorilla/securecookie"
)

func init() {
	gob.Register(cookieData{})
}

var ErrAttemptNotFound = errors.New("no login attempt cookie found")
var ErrAttemptExpired = errors.New("login attempt expired")
var ErrUserIDMismatch = errors.New("login attempt userID mismatch")

const defaultCookieName = "_login_attempt"

// cookieData is the value stored in the signed cookie.
type cookieData struct {
	UserID              string
	Satisfied           []string
	ExpiresAt           time.Time
	SessionKeepLoggedIn bool
}

// Store is a cookie-based login attempt store. Data is signed and encrypted
// via gorilla/securecookie, meeting the loginflow.Attempt requirement of an
// authenticated client token.
type Store struct {
	codec      *securecookie.SecureCookie
	cookieName string
}

// New creates a cookie-based login attempt store.
// hashKey must be 32 or 64 bytes; blockKey must be 16, 24, or 32 bytes.
func New(hashKey, blockKey []byte) (*Store, error) {
	hashL := len(hashKey)
	if hashL != 32 && hashL != 64 {
		return nil, fmt.Errorf("hashKey length should be 32 or 64 bytes")
	}
	blockKeyL := len(blockKey)
	if blockKeyL != 16 && blockKeyL != 24 && blockKeyL != 32 {
		return nil, fmt.Errorf("blockKey length should be 16, 24 or 32 bytes")
	}
	return &Store{
		codec:      securecookie.New(hashKey, blockKey),
		cookieName: defaultCookieName,
	}, nil
}

func (s *Store) Set(_ *http.Request, w http.ResponseWriter, a loginflow.Attempt) error {
	encoded, err := s.codec.Encode(s.cookieName, cookieData{
		UserID:              a.UserID,
		Satisfied:           a.Satisfied,
		ExpiresAt:           a.ExpiresAt,
		SessionKeepLoggedIn: a.SessionKeepLoggedIn,
	})
	if err != nil {
		return fmt.Errorf("login attempt cookie encode: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encoded,
		Path:     "/",
		Expires:  a.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Store) Get(r *http.Request, userID string) (loginflow.Attempt, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return loginflow.Attempt{}, ErrAttemptNotFound
	}
	var data cookieData
	if err := s.codec.Decode(s.cookieName, c.Value, &data); err != nil {
		return loginflow.Attempt{}, ErrAttemptNotFound
	}
	if data.UserID != userID {
		return loginflow.Attempt{}, ErrUserIDMismatch
	}
	if time.Now().After(data.ExpiresAt) {
		return loginflow.Attempt{}, ErrAttemptExpired
	}
	return loginflow.Attempt{
		UserID:              data.UserID,
		Satisfied:           data.Satisfied,
		ExpiresAt:           data.ExpiresAt,
		SessionKeepLoggedIn: data.SessionKeepLoggedIn,
	}, nil
}

func (s *Store) Clear(_ *http.Request, w http.ResponseWriter, _ string) error {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}
