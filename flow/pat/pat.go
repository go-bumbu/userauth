// Package pat exposes personal-access-token management (create, list,
// revoke) for an already-authenticated user. Token policy lives in
// service/pat; this package only binds it to a request identity. The
// caller's user ID always comes from the session (UserID func), never from
// the request body or path — users manage only their own tokens.
package pat

import (
	"fmt"
	"net/http"
	"time"

	patsvc "github.com/go-bumbu/userauth/service/pat"
)

// Flow binds a pat.Service to a request-identity source.
type Flow struct {
	// Service owns token policy. Required.
	Service *patsvc.Service
	// UserID extracts the authenticated user's canonical ID from the
	// request (e.g. from the cookieauth session context). Required.
	UserID func(r *http.Request) (string, error)
}

// check validates the flow wiring.
func (f *Flow) check() error {
	if f.Service == nil {
		return fmt.Errorf("pat flow: Service is required")
	}
	if f.UserID == nil {
		return fmt.Errorf("pat flow: UserID is required")
	}
	return nil
}

// Create mints a token for the request's user.
func (f *Flow) Create(r *http.Request, name string, scopes []string, expiresAt *time.Time) (string, patsvc.TokenRecord, error) {
	if err := f.check(); err != nil {
		return "", patsvc.TokenRecord{}, err
	}
	userID, err := f.UserID(r)
	if err != nil {
		return "", patsvc.TokenRecord{}, ErrNoIdentity
	}
	return f.Service.Mint(userID, name, scopes, expiresAt)
}

// List returns the request user's token records.
func (f *Flow) List(r *http.Request) ([]patsvc.TokenRecord, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	userID, err := f.UserID(r)
	if err != nil {
		return nil, ErrNoIdentity
	}
	return f.Service.List(userID)
}

// Revoke deletes one of the request user's tokens.
func (f *Flow) Revoke(r *http.Request, tokenID string) error {
	if err := f.check(); err != nil {
		return err
	}
	userID, err := f.UserID(r)
	if err != nil {
		return ErrNoIdentity
	}
	return f.Service.Revoke(userID, tokenID)
}

// ErrNoIdentity is returned when the request carries no authenticated user.
var ErrNoIdentity = fmt.Errorf("no authenticated user in request")
