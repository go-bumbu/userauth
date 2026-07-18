// Package login holds the demo examples for login flows: handlers that
// verify credentials and establish a session (password form, passwordless
// email code), as opposed to authentication methods that authenticate each
// request.
package login

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/loginflow"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// Password demonstrates username+password form login persisted in a cookie
// session, built on loginflow with a single-factor password policy. The flow
// keeps all credential failures (unknown user, disabled user, wrong password)
// indistinguishable; the demo owns the form parsing and rendering.
func Password(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
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
		Logger:        log,
	})
	if err != nil {
		panic("error instantiating session manager")
	}

	flow := &loginflow.Flow{
		Users:   users,
		Methods: []loginflow.Method{loginflow.PasswordMethod{Users: users}},
		Policy:  loginflow.RequireAny(loginflow.Chain{loginflow.MethodPassword}),
		Session: sessMgr, // single-factor policy: no attempt store needed
		Logger:  log,
	}

	r := mux.NewRouter()

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", rnd.ProtectedPage("content protected by session cookie"))
	protected.Use(sessMgr.Middleware)

	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rnd.Render(w, req, "login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username := strings.TrimSpace(req.FormValue("username"))
		password := req.FormValue("password")
		keepLoggedIn := req.FormValue("session_renew") == "on"

		res, err := flow.Submit(req, w, username, loginflow.MethodPassword, password, keepLoggedIn)
		if err != nil {
			log.Error("password login: flow error", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !res.Done {
			rnd.Render(w, req, "login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
			return
		}
		http.Redirect(w, req, "/password/protected", http.StatusSeeOther)
	})
	r.Path("/logout").Handler(logincookie.LogoutHandler(sessMgr, "/"))

	return r
}
