package main

import (
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/store"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/dbusers"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
)

var rnd = web.New()

var (
	dbUserMgr    *dbusers.DbManager
	userRegistry *store.Registry
)

func init() {
	var err error
	dbUserMgr, userRegistry, err = store.New()
	if err != nil {
		panic(err)
	}
}

var demoUsers = staticusers.Users{
	Users: []staticusers.User{
		{Id: "admin", HashPw: userauth.MustHashPw("admin"), Enabled: true},
		{Id: "demo", HashPw: userauth.MustHashPw("demo"), Enabled: true},
	},
}

func demoHandler() http.Handler {

	r := mux.NewRouter()

	// ===============================================
	// Basicauth — see examples/basicauth.go
	// ===============================================
	r.PathPrefix("/basic/").Handler(http.StripPrefix("/basic", examples.BasicAuth(logger, &demoUsers, rnd)))

	// ===============================================
	// Password form login (cookie session) — see examples/passwordlogin.go
	// ===============================================
	r.PathPrefix("/cookie/").Handler(http.StripPrefix("/cookie", examples.PasswordLogin(logger, &demoUsers, rnd)))

	// ===============================================
	// Header auth — see examples/headerauth.go
	// ===============================================
	r.PathPrefix("/header/").Handler(http.StripPrefix("/header", examples.HeaderAuth(logger, rnd)))

	// ===============================================
	// Passwordless email-code login — see examples/emaillogin.go
	// ===============================================
	r.PathPrefix("/emailcode/").Handler(http.StripPrefix("/emailcode", examples.EmailLogin(logger, rnd)))

	// ===============================================
	// User management — see examples/usersadmin.go
	// ===============================================
	r.PathPrefix("/users/").Handler(http.StripPrefix("/users", examples.UsersAdmin(logger, dbUserMgr, userRegistry, rnd)))

	// ===============================================
	// User registration — see examples/register.go
	// ===============================================
	reg := examples.NewRegister(logger, dbUserMgr, userRegistry, rnd)
	r.Path("/register").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Password)
	r.Path("/register/email").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Email)
	r.Path("/register/email/verify").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.EmailVerify)

	// ===============================================
	// User profile (self-service) — see profile.go
	// ===============================================
	r.PathPrefix("/profile/").Handler(http.StripPrefix("/profile", profileDemo()))

	// ===============================================
	// rest of the pages
	// ===============================================

	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		rnd.Render(writer, request, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(rnd.Favicon)

	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rnd.Render(w, r, "index.tmpl.html", nil)
	})
	return r
}

