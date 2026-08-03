package basicauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/support/hashutil"
)

// AuthHandler verifies if basic auth information is present in the request and allows to log-in if credentials match.
// If Enforce is set to true, the handler will signal the authenticator to stop evaluating any other authenticator
// but prompt the browser to ask for basicauth credentials.
// If Enforce is ste to false, the handler will only verify for existing basic auth headers, but eventually if
// the provided ones do not match a 401 is returned and the user is never promoted to provide credentials.
type AuthHandler struct {
	users   userauth.UserGetter
	message string
	enforce bool
	logger  *slog.Logger
}

const DefaultAuthMsg = "Authenticate"

func NewHandler(users userauth.UserGetter, msg string, enforce bool, l *slog.Logger) *AuthHandler {
	if msg == "" {
		msg = DefaultAuthMsg
	}

	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}

	a := AuthHandler{
		users:   users,
		message: msg,
		enforce: enforce,
		logger:  l.With("auth-handler", basicAuthName),
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
		var err error
		loggedIn, err = auth.verify(username, password)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
			return
		}
	}
	if auth.enforce {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, auth.message))
	}
	return
}

// verify checks the credentials against the user store. Unknown user, disabled
// user, wrong password and a malformed stored hash are all credential failures
// (false, nil); an error is an internal store failure.
func (auth *AuthHandler) verify(username, password string) (bool, error) {
	user, err := auth.users.GetUser(username)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) || errors.Is(err, userauth.ErrUserDisabled) {
			return false, nil
		}
		return false, err
	}
	if !user.Enabled {
		return false, nil
	}
	ok, err := hashutil.VerifyPassword(password, user.HashPw)
	if err != nil {
		return false, nil
	}
	return ok, nil
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
