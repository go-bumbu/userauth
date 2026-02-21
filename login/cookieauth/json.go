package cookieauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/authhandler/cookieauth"
)

// Payload is the JSON body for login requests.
type Payload struct {
	User           string `json:"username"`
	Pw             string `json:"password"`
	KeepMeLoggedIn bool   `json:"sessionRenew"`
	Redirect       string `json:"redirect,omitempty"`
}

// JsonAuthHandler returns an HTTP handler that accepts JSON POST login and establishes a session on success.
func JsonAuthHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
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

		if result.Authenticated {
			userID := result.UserID
			if userID == "" {
				userID = payload.User
			}
			err = sessMgr.LoginUser(r, w, userID, payload.KeepMeLoggedIn)
			if err != nil {
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
