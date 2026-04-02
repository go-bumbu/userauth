package auth

import "net/http"

// AuthHandler is implemented by session and other auth backends for use with chain authenticator.
type AuthHandler interface {
	Name() string
	HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool)
}
