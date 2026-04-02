package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth"
)

// Payload is the JSON body for login requests.
type Payload struct {
	User           string `json:"username"`
	Pw             string `json:"password"`
	KeepMeLoggedIn bool   `json:"sessionRenew"`
	Redirect       string `json:"redirect,omitempty"`
}

// loginResponse2FA is returned when password is valid but 2FA is required.
type loginResponse2FA struct {
	Requires2FA            bool                    `json:"requires2fa"`
	UserID                 string                  `json:"userID"`
	AvailableSecondFactors []userauth.SecondFactor `json:"available_second_factors"`
}

// UserLogin creates a session for an authenticated user.
// authhandler/cookieauth.Manager satisfies this implicitly.
type UserLogin interface {
	LoginUser(r *http.Request, w http.ResponseWriter, userID string, keepLoggedIn bool) error
}

// JsonAuthHandler returns an HTTP handler for POST /login. When the user has 2FA enabled,
// responds with 200 and { "requires2fa": true, "userID", "available_second_factors" } instead of creating a session.
//
// TODO: pendingDuration doesn't belong here — the handler shouldn't own a timeout for
// something controlled by the 2FA method. The expiry could come from the second factor
// implementations (each method knows its code lifetime), or be configured on the
// PendingLoginSetter at construction time. Revisit when wiring delivery-based 2FA.
func JsonAuthHandler(loginner UserLogin, auth *userauth.LoginHandler, pending PendingLoginSetter, pendingDuration time.Duration) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			logger.Debug("json login: failed to decode request body", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload.User == "" || payload.Pw == "" {
			logger.Debug("json login: empty username or password")
			http.Error(w, "User or Password cannot be empty", http.StatusBadRequest)
			return
		}

		logger.Debug("json login: attempting login", "username", payload.User)
		result, err := auth.CanLogin(payload.User, payload.Pw)
		if err != nil {
			switch {
			case errors.Is(err, userauth.ErrUserNotFound):
				logger.Debug("json login: user not found", "username", payload.User)
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			case errors.Is(err, userauth.ErrUserDisabled):
				logger.Debug("json login: user is disabled", "username", payload.User)
				http.Error(w, "User is disabled", http.StatusUnauthorized)
				return
			default:
				logger.Debug("json login: error checking credentials", "username", payload.User, "error", err)
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if result.Requires2FA {
			userID := result.UserID
			if userID == "" {
				userID = payload.User
			}
			if err := pending.SetPendingLogin(r, w, PendingLogin{
				UserID:         userID,
				KeepMeLoggedIn: payload.KeepMeLoggedIn,
				ExpiresAt:      time.Now().Add(pendingDuration),
			}); err != nil {
				logger.Debug("json login: failed to store pending login", "username", payload.User, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(loginResponse2FA{
				Requires2FA:            true,
				UserID:                 userID,
				AvailableSecondFactors: result.AvailableSecondFactors,
			})
			return
		}

		if result.Authenticated {
			userID := result.UserID
			if userID == "" {
				userID = payload.User
			}
			if err := loginner.LoginUser(r, w, userID, payload.KeepMeLoggedIn); err != nil {
				logger.Debug("json login: failed to create session", "username", payload.User, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			logger.Debug("json login: login successful", "username", payload.User)
			w.WriteHeader(http.StatusOK)
			return
		}
		logger.Debug("json login: invalid credentials", "username", payload.User)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
