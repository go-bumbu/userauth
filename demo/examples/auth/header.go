package auth

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/auth/headerauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/gorilla/mux"
)

// Header demonstrates authentication from a trusted request header
// (X-User-Auth), the pattern used behind a reverse proxy that injects the
// already-authenticated user's identity. The proxy owns the trust decision:
// the deployment must guarantee clients cannot set the header themselves.
func Header(log *slog.Logger, rnd *web.Renderer) http.Handler {
	r := mux.NewRouter()
	hauth := headerauth.New(headerauth.UserAuthHeader, true, log)

	r.Path("/protected").Methods(http.MethodGet).Handler(
		hauth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			data := hauth.GetData(req)
			rnd.Render(w, req, "protected.tmpl.html", map[string]any{
				"text": fmt.Sprintf("content protected by header X-User-Auth - authenticated as: %s", data.UserName),
			})
		})),
	)

	return r
}
