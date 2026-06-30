package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

func cookieAuthDemo() http.Handler {
	r := mux.NewRouter()
	login := userauth.LoginHandler{UserStore: &demoUsers}

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("error instantiating cookie store: %v", err))
	}

	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        logger,
	})
	if err != nil {
		panic("error instantiating session manager")
	}

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", rnd.ProtectedPage("content protected by session cookie"))
	protected.Use(sessMgr.Middleware)

	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rnd.Render(w, r, "login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).Handler(
		logincookie.FormAuthHandler(sessMgr, &login, "/cookie/protected"))
	r.Path("/logout").Handler(
		logincookie.LogoutHandler(sessMgr, "/"))

	return r
}
