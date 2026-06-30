package main

import (
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/auth/basicauth"
	"github.com/gorilla/mux"
)

func basicAuthDemo() http.Handler {
	r := mux.NewRouter()
	login := userauth.LoginHandler{UserStore: &demoUsers}

	enforceAuth := basicauth.NewHandler(login, "", true, logger)
	r.Handle("/enforce", enforceAuth.Middleware(rnd.ProtectedPage("basicauth enforce mode - browser prompts for credentials when not authenticated"))).Methods(http.MethodGet)

	silentAuth := basicauth.NewHandler(login, "", false, logger)
	r.Handle("/silent", silentAuth.Middleware(rnd.ProtectedPage("basicauth silent mode - returns 401 without prompting the browser"))).Methods(http.MethodGet)

	return r
}
