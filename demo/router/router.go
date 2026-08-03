package router

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/examples/auth"
	"github.com/go-bumbu/userauth/demo/examples/login"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

type Cfg struct {
	Logger      *slog.Logger        // structured logger handed to every example
	Users       *userdb.Store       // DB-backed store, used by profile, register, usersadmin
	StaticUsers userauth.UserGetter // static (in-memory) credentials, used by basicauth, headerauth + passwordlogin
	Web         *web.Renderer       // server-side template renderer and static-asset server
}

func New(cfg Cfg) http.Handler {
	r := mux.NewRouter()

	// authentication methods: each request is authenticated on its own

	// protect with HTTP Basic auth middleware (browser prompts for credentials)
	r.PathPrefix("/basic/").Handler(http.StripPrefix("/basic", auth.Basic(cfg.Logger, cfg.StaticUsers, cfg.Web)))

	// protect with trusted-header auth middleware (identity injected by a reverse proxy)
	r.PathPrefix("/header/").Handler(http.StripPrefix("/header", auth.Header(cfg.Logger, cfg.Web)))

	// protect with an encrypted cookie session (the session itself, isolated from any login flow)
	r.PathPrefix("/cookie/").Handler(http.StripPrefix("/cookie", auth.Cookie(cfg.Logger, cfg.Web)))

	// login flows: credentials are verified once and a cookie session is established

	// password form login
	r.PathPrefix("/password/").Handler(http.StripPrefix("/password", login.Password(cfg.Logger, cfg.StaticUsers, cfg.Web)))

	// passwordless login via a one-time code "emailed" to the user
	r.PathPrefix("/emailcode/").Handler(http.StripPrefix("/emailcode", login.Email(cfg.Logger, cfg.Web)))

	// self-registration: password-based and email-code-based sign-up
	reg := examples.NewRegister(cfg.Logger, cfg.Users, cfg.Web)
	r.Path("/register").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Password)
	r.Path("/register/email").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Email)
	r.Path("/register/email/verify").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.EmailVerify)

	// the same registration flows as a JSON API for SPAs (register/handlers preset)
	api := examples.RegisterAPI(cfg.Logger, cfg.Users)
	r.Path("/api/register").Methods(http.MethodPost).Handler(api.RegisterHandler())
	r.Path("/api/register/verify").Methods(http.MethodPost).Handler(api.VerifyHandler())
	r.Path("/api/register/request-code").Methods(http.MethodPost).Handler(api.RequestCodeHandler())

	// authenticated self-service area: password/email change and TOTP 2FA
	r.PathPrefix("/profile/").Handler(http.StripPrefix("/profile", examples.Profile(cfg.Logger, cfg.Users, cfg.Web)))

	// admin user management: list and manage the accounts in the DB store
	r.PathPrefix("/useradmin/").Handler(http.StripPrefix("/useradmin", examples.UsersAdmin(cfg.Logger, cfg.Users, cfg.Web)))

	// shared assets and the landing page
	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(cfg.Web.Favicon)
	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.Web.Render(w, req, "index.tmpl.html", nil)
	})
	return r
}
