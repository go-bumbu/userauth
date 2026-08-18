package router

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/examples/admin"
	"github.com/go-bumbu/userauth/demo/examples/auth"
	"github.com/go-bumbu/userauth/demo/examples/login"
	"github.com/go-bumbu/userauth/demo/examples/profile"
	"github.com/go-bumbu/userauth/demo/examples/register"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
	"github.com/gorilla/mux"
)

type Cfg struct {
	Logger      *slog.Logger        // structured logger handed to every example
	Stores      preset.Stores       // the full GORM setup, used by profile, register, admin
	MFA         mfa.Services        // TOTP + recovery code services over Users, shared by profile and the login API
	StaticUsers userauth.UserGetter // static (in-memory) credentials, used by basicauth, headerauth + passwordlogin
	Web         *web.Renderer       // server-side template renderer and static-asset server
}

// New assembles the demo: each library aspect contributes a Section that both
// mounts its handlers and describes itself; the index page is rendered from
// the same section data, so it always reflects what is actually mounted.
func New(cfg Cfg) http.Handler {
	sections := []examples.Section{
		auth.Section(cfg.Logger, cfg.StaticUsers, cfg.Web),
		login.Section(cfg.Logger, cfg.StaticUsers, cfg.Stores.Users, cfg.MFA, cfg.Web),
		register.Section(cfg.Logger, cfg.Stores.Users, cfg.Web),
		profile.Section(cfg.Logger, cfg.Stores, cfg.MFA, cfg.Web),
		admin.Section(cfg.Logger, cfg.Stores.Users, cfg.Web),
	}

	r := mux.NewRouter()
	for _, s := range sections {
		for _, e := range s.Examples {
			if e.Mount != nil {
				e.Mount(r)
			}
		}
	}

	// shared assets and the landing page
	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(cfg.Web.Favicon)
	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "index.tmpl.html", map[string]any{"Sections": sections})
	})
	return r
}
