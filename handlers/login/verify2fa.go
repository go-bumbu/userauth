package login

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth"
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

// Verify2FAPayload is the JSON body for POST /login/verify-totp, verify-recovery, verify-email, verify-sms.
type Verify2FAPayload struct {
	UserID string `json:"userID"`
	Code   string `json:"code"`
}

// Verify2FAHandler returns an HTTP handler that verifies a 2FA code and creates a session on success.
// Body: { "userID", "code", "sessionRenew" }.
//
// The verify func takes (userID, code) and returns a LoginResult.
// Pass one of the LoginHandler methods to select the verification strategy:
//
//   - auth.VerifyTOTP          — authenticator app (time-based one-time password)
//   - auth.VerifyRecoveryCode  — single-use recovery code
//   - auth.VerifyEmailCode     — one-time code sent via email
//   - auth.VerifySMSCode       — one-time code sent via SMS
func Verify2FAHandler(Loginer UserLogin, pending PendingLoginGetter, verify func(string, string) (userauth.LoginResult, error), logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Verify2FAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload.UserID == "" || payload.Code == "" {
			http.Error(w, "userID and code required", http.StatusBadRequest)
			return
		}
		pendingData, err := pending.GetPendingLogin(r, payload.UserID)
		if err != nil {
			logger.Debug("verify 2FA: pending login not found or expired", "userID", payload.UserID, "error", err)
			http.Error(w, "pending login expired or not found", http.StatusUnauthorized)
			return
		}
		if time.Now().After(pendingData.ExpiresAt) {
			logger.Debug("verify 2FA: pending login expired", "userID", payload.UserID, "expiresAt", pendingData.ExpiresAt)
			_ = pending.ClearPendingLogin(r, w, payload.UserID)
			http.Error(w, "pending login expired", http.StatusUnauthorized)
			return
		}
		result, err := verify(payload.UserID, payload.Code)
		if err != nil {
			logger.Debug("verify 2FA: error", "userID", payload.UserID, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !result.Authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if err := Loginer.LoginUser(r, w, payload.UserID, pendingData.KeepMeLoggedIn); err != nil {
			logger.Debug("verify 2FA: failed to create session", "userID", payload.UserID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := pending.ClearPendingLogin(r, w, payload.UserID); err != nil {
			logger.Debug("verify 2FA: failed to clear pending login", "userID", payload.UserID, "error", err)
		}
		w.WriteHeader(http.StatusOK)
	})
}
