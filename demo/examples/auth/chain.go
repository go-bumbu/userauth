package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/basicauth"
	"github.com/go-bumbu/userauth/auth/chain"
	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// Chain demonstrates chain.Authenticator: several auth handlers are evaluated
// in order and the first success wins. Here a cookie session is tried first
// (browsers that logged in once), then non-enforcing basic auth (API clients
// sending an Authorization header); when both fail the unauthorized callback
// redirects to a login endpoint instead of answering 401.
func Chain(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("chain: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_chain_demo_auth",
		SessionDur:    10 * time.Minute,
		MaxSessionDur: time.Hour,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("chain: session manager: %w", err))
	}

	// basic auth stays non-enforcing so a failed header check falls through
	// to the callback instead of prompting the browser
	basic := basicauth.NewHandler(users, "", false, log)

	authenticator := chain.New(
		[]chain.AuthHandler{sessMgr, basic},
		log,
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/chain/login", http.StatusSeeOther)
		},
		nil,
	)

	r := mux.NewRouter()

	// start a session for a fixed user so the cookie link of the chain can
	// be exercised; a real application runs a proper login flow instead
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := sessMgr.LoginUser(req, w, "demo", false); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/chain/protected", http.StatusSeeOther)
	})

	r.Path("/protected").Methods(http.MethodGet).Handler(
		authenticator.Middleware(rnd.ProtectedPage("content protected by an auth chain: cookie session, then basic auth")),
	)

	r.Path("/logout").Handler(cookieauth.LogoutHandler(sessMgr, "/"))
	return r
}
