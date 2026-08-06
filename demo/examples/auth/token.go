package auth

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/tokenauth"
	"github.com/go-bumbu/userauth/demo/web"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	patmemory "github.com/go-bumbu/userauth/service/pat/store/memory"
	"github.com/gorilla/mux"
)

// Token demonstrates PAT authentication: /new mints a token for the demo
// user (demo convenience only — real applications mint via the session-
// authenticated flow/pat endpoints), /protected accepts it as
// "Authorization: Bearer <token>" or "X-Api-Token: <token>".
func Token(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	pats, err := patsvc.NewService(patmemory.New(), users, patsvc.Opts{Logger: log})
	if err != nil {
		panic(fmt.Errorf("token demo: %v", err))
	}
	tokenAuth, err := tokenauth.New(tokenauth.Cfg{
		Verifier:     pats.ChainVerifier(),
		CustomHeader: "X-Api-Token",
		Logger:       log,
	})
	if err != nil {
		panic(fmt.Errorf("token demo: %v", err))
	}

	r := mux.NewRouter()
	r.Path("/new").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		plaintext, _, err := pats.Mint("demo", "demo token", nil, nil)
		if err != nil {
			http.Error(w, "could not mint token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "token: %s\n\ntry:\n  curl -H \"Authorization: Bearer %s\" http://localhost:8085/token/protected\n", plaintext, plaintext)
	})
	r.Path("/protected").Handler(tokenAuth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, err := tokenauth.CtxGetRequestData(req)
		if err != nil {
			http.Error(w, "context error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "authenticated as %s via token %q\n", data.UserID, data.Name)
	})))
	return r
}
