// Package auth holds the demo examples for authentication methods: handlers
// that authenticate each request (basic auth, trusted header, cookie session)
// as opposed to login flows that establish a session.
package auth

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/auth/basicauth"
	"github.com/gorilla/mux"
)

// Basic demonstrates HTTP Basic authentication in two modes: "enforce"
// sends a WWW-Authenticate challenge so the browser pops up a credentials
// prompt, while "silent" returns 401 without prompting.
func Basic(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	r := mux.NewRouter()

	enforceAuth := basicauth.NewHandler(users, "", true, log)
	r.Handle("/enforce", enforceAuth.Middleware(rnd.ProtectedPage("basicauth enforce mode - browser prompts for credentials when not authenticated"))).Methods(http.MethodGet)

	silentAuth := basicauth.NewHandler(users, "", false, log)
	r.Handle("/silent", silentAuth.Middleware(rnd.ProtectedPage("basicauth silent mode - returns 401 without prompting the browser"))).Methods(http.MethodGet)

	return r
}
