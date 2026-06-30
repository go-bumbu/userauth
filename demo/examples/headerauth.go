package examples

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/headerauth"
	"github.com/gorilla/mux"
)

func HeaderAuth(log *slog.Logger, rnd *web.Renderer) http.Handler {
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
