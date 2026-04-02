package cookie

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/handlers/login"
	"github.com/gorilla/securecookie"
)

func init() {
	gob.Register(cookieData{})
}

var ErrPendingLoginNotFound = errors.New("no pending login cookie found")
var ErrPendingLoginExpired = errors.New("pending login expired")
var ErrUserIDMismatch = errors.New("pending login userID mismatch")

const defaultCookieName = "_pending_login"

// cookieData is the value stored in the signed cookie.
type cookieData struct {
	UserID         string
	KeepMeLoggedIn bool
	ExpiresAt      time.Time
}

// Store is a cookie-based pending login store. Data is signed and encrypted
// via gorilla/securecookie — no server-side state required.
type Store struct {
	codec      *securecookie.SecureCookie
	cookieName string
}

// New creates a cookie-based pending login store.
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

func (s *Store) SetPendingLogin(_ *http.Request, w http.ResponseWriter, data login.PendingLogin) error {
	encoded, err := s.codec.Encode(s.cookieName, cookieData{
		UserID:         data.UserID,
		KeepMeLoggedIn: data.KeepMeLoggedIn,
		ExpiresAt:      data.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("pending login cookie encode: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Store) GetPendingLogin(r *http.Request, userID string) (login.PendingLogin, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return login.PendingLogin{}, ErrPendingLoginNotFound
	}
	var data cookieData
	if err := s.codec.Decode(s.cookieName, c.Value, &data); err != nil {
		return login.PendingLogin{}, ErrPendingLoginNotFound
	}
	if data.UserID != userID {
		return login.PendingLogin{}, ErrUserIDMismatch
	}
	return login.PendingLogin{
		UserID:         data.UserID,
		KeepMeLoggedIn: data.KeepMeLoggedIn,
		ExpiresAt:      data.ExpiresAt,
	}, nil
}

func (s *Store) ClearPendingLogin(_ *http.Request, w http.ResponseWriter, _ string) error {
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
