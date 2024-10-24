package basicauth

import (
	"errors"
	"fmt"
	"github.com/go-bumbu/userauth"
	"io"
	"log/slog"
	"net/http"
)

type Basic struct {
	User         userauth.LoginHandler
	Message      string
	Redirect     string
	RedirectCode int
	Logger       *slog.Logger
}

func (auth *Basic) Middleware(next http.Handler) http.Handler {
	if auth.Logger == nil {
		auth.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if auth.Message == "" {
		auth.Message = "Authenticate"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {

			canLogin, err := auth.User.CanLogin(username, password)
			if err != nil {
				// only return an error if it's NOT user not found or user disabled
				switch {
				case errors.Is(err, userauth.NotFoundErr), errors.Is(err, userauth.UserDisabledErr):
					// ignore the known errors and
				default:
					http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
					return
				}
			}

			if canLogin {
				auth.Logger.Info("login successful", "username", username)
				next.ServeHTTP(w, r)
				return
			} else {
				auth.Logger.Info("login unsuccessful", "username", username)
			}
		}

		if auth.Redirect != "" {
			http.Redirect(w, r, auth.Redirect, auth.RedirectCode)
			return
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, auth.Message))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
