package cookieauth

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/cookieauth"
)

// Verify2FAPayload is the JSON body for POST /login/verify-totp, verify-recovery, verify-email, verify-sms.
type Verify2FAPayload struct {
	UserID         string `json:"userID"`
	Code           string `json:"code"`
	KeepMeLoggedIn bool   `json:"sessionRenew"`
}

func verify2FAAndLogin(w http.ResponseWriter, r *http.Request, sessMgr *cookieauth.Manager, userID, code string, keepMeLoggedIn bool, verify func(string, string) (userauth.LoginResult, error), logger *slog.Logger) {
	if userID == "" || code == "" {
		http.Error(w, "userID and code required", http.StatusBadRequest)
		return
	}
	result, err := verify(userID, code)
	if err != nil {
		logger.Debug("verify 2FA: error", "userID", userID, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !result.Authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := sessMgr.LoginUser(r, w, userID, keepMeLoggedIn); err != nil {
		logger.Debug("verify 2FA: failed to create session", "userID", userID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// VerifyTOTPHandler returns an HTTP handler for POST /login/verify-totp. Body: { "userID", "code", "sessionRenew" }. On success creates session.
func VerifyTOTPHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Verify2FAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verify2FAAndLogin(w, r, sessMgr, payload.UserID, payload.Code, payload.KeepMeLoggedIn, auth.VerifyTOTP, logger)
	})
}

// VerifyRecoveryCodeHandler returns an HTTP handler for POST /login/verify-recovery. Body: { "userID", "code", "sessionRenew" }. On success creates session.
func VerifyRecoveryCodeHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Verify2FAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verify2FAAndLogin(w, r, sessMgr, payload.UserID, payload.Code, payload.KeepMeLoggedIn, auth.VerifyRecoveryCode, logger)
	})
}

// VerifyEmailCodeHandler returns an HTTP handler for POST /login/verify-email. Body: { "userID", "code", "sessionRenew" }. On success creates session.
func VerifyEmailCodeHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Verify2FAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verify2FAAndLogin(w, r, sessMgr, payload.UserID, payload.Code, payload.KeepMeLoggedIn, auth.VerifyEmailCode, logger)
	})
}

// VerifySMSCodeHandler returns an HTTP handler for POST /login/verify-sms. Body: { "userID", "code", "sessionRenew" }. On success creates session.
func VerifySMSCodeHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Verify2FAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verify2FAAndLogin(w, r, sessMgr, payload.UserID, payload.Code, payload.KeepMeLoggedIn, auth.VerifySMSCode, logger)
	})
}
