package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/go-bumbu/userauth/verificationcode/memory"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// emailCodeUsers is the hardcoded allow-list of emails permitted to log in
// passwordlessly. No HashPw: login never verifies a password.
var emailCodeUsers = staticusers.Users{Users: []staticusers.User{
	{Id: "admin@example.com", Enabled: true},
	{Id: "demo@example.com", Enabled: true},
}}

var emailLoginCodeStore = memory.New()
var emailLoginCodeSvc = &userauth.VerificationCodeService{
	Store:      emailLoginCodeStore.Store,
	CodeLength: 6,
	Expiry:     10 * time.Minute,
}

type pendingEmailLogin struct {
	plainCode string
	expiresAt time.Time
}

// pendingEmailLogins keeps the plain code per email so the verify page can
// re-display it (the memory store only retains the hash). Demo-only.
var pendingEmailLogins = struct {
	mu    sync.Mutex
	items map[string]pendingEmailLogin
}{items: make(map[string]pendingEmailLogin)}

func emailCodeLoginAddresses() []string {
	addrs := make([]string, 0, len(emailCodeUsers.Users))
	for _, u := range emailCodeUsers.Users {
		addrs = append(addrs, u.Id)
	}
	return addrs
}

func emailCodeDemo() http.Handler {
	r := mux.NewRouter()

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("emailcode: error instantiating cookie store: %v", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_emailcode_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        logger,
	})
	if err != nil {
		panic(fmt.Errorf("emailcode: error instantiating session manager: %v", err))
	}

	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		renderTmpl(w, req, "emailcode_login.tmpl.html", map[string]any{"Emails": emailCodeLoginAddresses()})
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(emailCodeRequestHandler)
	r.Path("/logout").Handler(logincookie.LogoutHandler(sessMgr, "/"))

	return r
}

func emailCodeRequestHandler(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		renderTmpl(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Email is required.",
			"Emails": emailCodeLoginAddresses(),
		})
		return
	}

	user, err := emailCodeUsers.GetUser(email)
	if err != nil || !user.Enabled {
		renderTmpl(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Unknown email. Use one of the demo addresses listed below.",
			"Email":  email,
			"Emails": emailCodeLoginAddresses(),
		})
		return
	}

	code, expiresAt, err := emailLoginCodeSvc.Generate(email)
	if err != nil {
		renderTmpl(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Could not generate login code.",
			"Email":  email,
			"Emails": emailCodeLoginAddresses(),
		})
		return
	}

	pendingEmailLogins.mu.Lock()
	pendingEmailLogins.items[email] = pendingEmailLogin{plainCode: code, expiresAt: expiresAt}
	pendingEmailLogins.mu.Unlock()

	http.Redirect(w, r, "/emailcode/login/verify?email="+url.QueryEscape(email), http.StatusSeeOther)
}
