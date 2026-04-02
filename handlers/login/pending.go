package login

import (
	"net/http"
	"time"
)

// PendingLogin holds state between initial login and 2FA verification.
type PendingLogin struct {
	UserID         string
	KeepMeLoggedIn bool
	ExpiresAt      time.Time
}

// PendingLoginSetter stores pending login state when 2FA is required.
// Implementations key by data.UserID.
type PendingLoginSetter interface {
	SetPendingLogin(r *http.Request, w http.ResponseWriter, data PendingLogin) error
}

// PendingLoginGetter retrieves and clears pending login state during 2FA verification.
type PendingLoginGetter interface {
	GetPendingLogin(r *http.Request, userID string) (PendingLogin, error)
	ClearPendingLogin(r *http.Request, w http.ResponseWriter, userID string) error
}
