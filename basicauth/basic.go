package basicauth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
)

type Basic struct {
	User         userauth.UserLogin
	Message      string
	Redirect     string
	RedirectCode int
	logger       *slog.Logger
}

func (auth *Basic) Middleware(next http.Handler) http.Handler {
	if auth.logger == nil {
		slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if auth.Message == "" {
		auth.Message = "Authenticate"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			if auth.User.CanLogin(username, password) {
				auth.logger.Info("login successful", "username", username)
				next.ServeHTTP(w, r)
				return
			} else {
				auth.logger.Info("login unsuccessful", "username", username)
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
