package examples

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/basicauth"
	"github.com/gorilla/mux"
)

func BasicAuth(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	r := mux.NewRouter()
	login := userauth.LoginHandler{UserStore: users}

	enforceAuth := basicauth.NewHandler(login, "", true, log)
	r.Handle("/enforce", enforceAuth.Middleware(rnd.ProtectedPage("basicauth enforce mode - browser prompts for credentials when not authenticated"))).Methods(http.MethodGet)

	silentAuth := basicauth.NewHandler(login, "", false, log)
	r.Handle("/silent", silentAuth.Middleware(rnd.ProtectedPage("basicauth silent mode - returns 401 without prompting the browser"))).Methods(http.MethodGet)

	return r
}
