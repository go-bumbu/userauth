package router

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/store"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/dbuser"
	"github.com/gorilla/mux"
)

// Cfg holds the dependencies for the demo router.
type Cfg struct {
	Logger      *slog.Logger
	Users       *dbuser.Store       // DB-backed store: profile, register, usersadmin
	Registry    *store.Registry     // shared user-id list for register + usersadmin
	StaticUsers userauth.UserGetter // static credentials: basicauth + passwordlogin
	Web         *web.Renderer
}

// New builds the top-level demo HTTP handler, mounting each library example.
func New(cfg Cfg) http.Handler {
	r := mux.NewRouter()

	r.PathPrefix("/basic/").Handler(http.StripPrefix("/basic", examples.BasicAuth(cfg.Logger, cfg.StaticUsers, cfg.Web)))
	r.PathPrefix("/cookie/").Handler(http.StripPrefix("/cookie", examples.PasswordLogin(cfg.Logger, cfg.StaticUsers, cfg.Web)))
	r.PathPrefix("/header/").Handler(http.StripPrefix("/header", examples.HeaderAuth(cfg.Logger, cfg.Web)))
	r.PathPrefix("/emailcode/").Handler(http.StripPrefix("/emailcode", examples.EmailLogin(cfg.Logger, cfg.Web)))
	r.PathPrefix("/users/").Handler(http.StripPrefix("/users", examples.UsersAdmin(cfg.Logger, cfg.Users, cfg.Registry, cfg.Web)))

	reg := examples.NewRegister(cfg.Logger, cfg.Users, cfg.Registry, cfg.Web)
	r.Path("/register").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Password)
	r.Path("/register/email").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Email)
	r.Path("/register/email/verify").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.EmailVerify)

	r.PathPrefix("/profile/").Handler(http.StripPrefix("/profile", examples.Profile(cfg.Logger, cfg.Users, cfg.Web)))

	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(cfg.Web.Favicon)
	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "index.tmpl.html", nil)
	})
	return r
}
