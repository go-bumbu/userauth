package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// Cookie demonstrates cookie-session authentication in isolation: the
// Middleware authenticates each request from an encrypted session cookie.
// Establishing the session is kept intentionally trivial (a GET that logs in
// a fixed demo user) to focus on the authentication side — see the login
// examples for real credential verification in front of LoginUser.
func Cookie(log *slog.Logger, rnd *web.Renderer) http.Handler {
	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("cookie: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_cookie_demo_auth",
		SessionDur:    10 * time.Minute,
		MaxSessionDur: time.Hour,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("cookie: session manager: %w", err))
	}

	r := mux.NewRouter()

	// start a session for a fixed user; a real application verifies
	// credentials first and calls LoginUser on success
	r.Path("/start").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := sessMgr.LoginUser(req, w, "demo", false); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/cookie/protected", http.StatusSeeOther)
	})

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ud, err := cookieauth.CtxGetUserData(req)
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		rnd.Render(w, req, "protected.tmpl.html", map[string]any{
			"text": fmt.Sprintf("content protected by session cookie - authenticated as: %s", ud.UserId),
		})
	}))
	protected.Use(sessMgr.Middleware)

	r.Path("/end").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := sessMgr.LogoutUser(req, w); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/", http.StatusSeeOther)
	})

	return r
}
