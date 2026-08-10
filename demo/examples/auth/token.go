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
	"github.com/go-bumbu/userauth/auth/tokenauth"
	"github.com/go-bumbu/userauth/demo/web"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	patmemory "github.com/go-bumbu/userauth/service/pat/store/memory"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// Token demonstrates PAT authentication as a chain member: /new mints a token
// for the demo user (demo convenience only — real applications mint via the
// session-authenticated flow/pat endpoints), /protected is guarded by a chain
// that tries cookie session, then PAT token, then basic auth — mirroring the
// production pattern where tokens, sessions, and fallback auth coexist.
func Token(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	pats, err := patsvc.NewService(patmemory.New(), users, patsvc.Opts{Logger: log})
	if err != nil {
		panic(fmt.Errorf("token demo: %v", err))
	}

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("token demo: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_token_demo_auth",
		SessionDur:    10 * time.Minute,
		MaxSessionDur: time.Hour,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("token demo: session manager: %w", err))
	}

	tokenAuth, err := tokenauth.New(tokenauth.Cfg{
		Verifier:     pats.ChainVerifier(),
		CustomHeader: "X-Api-Token",
		Logger:       log,
	})
	if err != nil {
		panic(fmt.Errorf("token demo: %v", err))
	}

	basic := basicauth.NewHandler(users, "", false, log)

	authenticator := chain.New(
		[]chain.AuthHandler{sessMgr, tokenAuth, basic},
		log,
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		},
		nil,
	)

	r := mux.NewRouter()
	r.Path("/new").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		plaintext, _, err := pats.Mint("demo", "demo token", nil, nil, patsvc.HashOnly)
		if err != nil {
			http.Error(w, "could not mint token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "token: %s\n\ntry:\n  curl -H \"Authorization: Bearer %s\" http://localhost:8085/token/protected\n", plaintext, plaintext)
	})
	r.Path("/protected").Methods(http.MethodGet).Handler(
		authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			data, err := tokenauth.CtxGetRequestData(req)
			if err == nil {
				// authenticated via token
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = fmt.Fprintf(w, "authenticated as %s via token %q\n", data.UserID, data.Name)
				return
			}
			// authenticated via cookie session or basic auth
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = fmt.Fprint(w, "authenticated (cookie session or basic auth)\n")
		})),
	)
	return r
}
