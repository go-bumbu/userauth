package headerauth

import (
	"log/slog"
	"net/http"
)

type HeaderHandler struct {
	header  string
	enforce bool
	logger  *slog.Logger
}

const UserAuthHeader = "X-User-Auth"

func New(checkHeader string, enforce bool, l *slog.Logger) *HeaderHandler {

	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}

	if checkHeader == "" {
		checkHeader = UserAuthHeader
	}

	a := HeaderHandler{
		header:  checkHeader,
		enforce: enforce,
		logger:  l.With("auth-handler", authName),
	}
	return &a
}

const authName = "httpheader"

func (auth *HeaderHandler) Name() string {
	return authName
}

func (auth *HeaderHandler) HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool) {
	l, s, _ := auth.handleAuth(w, r)
	return l, s
}
func (auth *HeaderHandler) handleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool, username string) {
	allowAccess = false

	stopEvaluation = false
	if auth.enforce {
		stopEvaluation = true
	}

	userHeader := r.Header.Get(auth.header)
	if userHeader != "" {
		allowAccess = true
		username = userHeader
		return
	}
	return
}

func (auth *HeaderHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canLogin, _, username := auth.handleAuth(w, r)
		if canLogin {
			auth.logger.Debug("login successful", "username", username)
			next.ServeHTTP(w, r)
			return
		} else {
			auth.logger.Debug("login unsuccessful", "username", username)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

type RequestData struct {
	UserName string
	Groups   []string // TODO groups are not implemented yet
}

func (auth *HeaderHandler) GetData(r *http.Request) RequestData {
	userHeader := r.Header.Get(auth.header)
	return RequestData{UserName: userHeader}
}
