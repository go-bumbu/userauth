package basicauth

import (
	"errors"
	"fmt"
	"github.com/go-bumbu/userauth"
	"log/slog"
	"net/http"
)

// AuthHandler verifies if basic auth information is present in the request and allows to log-in if credentials match.
// If Enforce is set to true, the handler will signal the authenticator to stop evaluating any other authenticator
// but prompt the browser to ask for basicauth credentials.
// If Enforce is ste to false, the handler will only verify for existing basic auth headers, but eventually if
// the provided ones do not match a 401 is returned and the user is never promoted to provide credentials.
type AuthHandler struct {
	loginHandler userauth.LoginHandler
	message      string
	enforce      bool
	logger       *slog.Logger
}

const DefaultAuthMsg = "Authenticate"

func NewHandler(loginHandler userauth.LoginHandler, msg string, enforce bool, l *slog.Logger) *AuthHandler {
	if msg == "" {
		msg = DefaultAuthMsg
	}

	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}

	a := AuthHandler{
		loginHandler: loginHandler,
		message:      msg,
		enforce:      enforce,
		logger:       l.With("auth-handler", basicAuthName),
	}
	return &a
}

const basicAuthName = "basicauth"

func (auth *AuthHandler) Name() string {
	return basicAuthName
}

func (auth *AuthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) (loggedIn, stopEvaluation bool) {
	l, s, _ := auth.handleAuth(w, r)
	return l, s
}

func (auth *AuthHandler) handleAuth(w http.ResponseWriter, r *http.Request) (loggedIn, stopEvaluation bool, username string) {

	stopEvaluation = false
	if auth.enforce {
		stopEvaluation = true
	}

	username, password, ok := r.BasicAuth()
	loggedIn = false
	if ok {
		canLogin, err := auth.loginHandler.CanLogin(username, password)
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
			loggedIn = true
		}
	}
	if auth.enforce {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, auth.message))
	}
	return
}

func (auth *AuthHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canLogin, _, userName := auth.handleAuth(w, r)
		if canLogin {
			auth.logger.Debug("login successful", "username", userName)
			next.ServeHTTP(w, r)
			return
		} else {
			auth.logger.Debug("login unsuccessful", "username", userName)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

	})
}
