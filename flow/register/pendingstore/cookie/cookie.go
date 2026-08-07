// Package cookie provides a cookie-based register.PendingStore. The pending
// registration travels in a signed and encrypted cookie
// (gorilla/securecookie), so no server-side state is required — suitable for
// multi-instance deployments that share the same keys.
//
// The cookie carries the bcrypt password hash of the registration in
// progress; the encryption keeps it opaque to the client, and the signature
// prevents tampering with the satisfied-checks claim.
package cookie

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/flow/register"
	"github.com/gorilla/securecookie"
)

func init() {
	gob.Register(cookieData{})
}

var ErrRegistrationNotFound = errors.New("no pending registration cookie found")
var ErrRegistrationExpired = errors.New("pending registration expired")
var ErrLoginIDMismatch = errors.New("pending registration loginID mismatch")

const defaultCookieName = "_pending_registration"

// cookieData is the value stored in the signed cookie.
type cookieData struct {
	LoginID    string
	PassHash   string
	Email      string
	InviteCode string
	Satisfied  []string
	ExpiresAt  time.Time
}

// Store is a cookie-based pending registration store. Data is signed and
// encrypted via gorilla/securecookie, meeting the register.Registration
// requirement of an authenticated client token.
type Store struct {
	codec      *securecookie.SecureCookie
	cookieName string
}

// New creates a cookie-based pending registration store.
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

func (s *Store) Set(_ *http.Request, w http.ResponseWriter, reg register.Registration) error {
	encoded, err := s.codec.Encode(s.cookieName, cookieData{
		LoginID:    reg.LoginID,
		PassHash:   reg.PassHash,
		Email:      reg.Email,
		InviteCode: reg.InviteCode,
		Satisfied:  reg.Satisfied,
		ExpiresAt:  reg.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("pending registration cookie encode: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encoded,
		Path:     "/",
		Expires:  reg.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Store) Get(r *http.Request, loginID string) (register.Registration, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return register.Registration{}, ErrRegistrationNotFound
	}
	var data cookieData
	if err := s.codec.Decode(s.cookieName, c.Value, &data); err != nil {
		return register.Registration{}, ErrRegistrationNotFound
	}
	if data.LoginID != loginID {
		return register.Registration{}, ErrLoginIDMismatch
	}
	if time.Now().After(data.ExpiresAt) {
		return register.Registration{}, ErrRegistrationExpired
	}
	return register.Registration{
		LoginID:    data.LoginID,
		PassHash:   data.PassHash,
		Email:      data.Email,
		InviteCode: data.InviteCode,
		Satisfied:  data.Satisfied,
		ExpiresAt:  data.ExpiresAt,
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
