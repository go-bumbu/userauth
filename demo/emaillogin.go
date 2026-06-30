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
		rnd.Render(w, req, "emailcode_login.tmpl.html", map[string]any{"Emails": emailCodeLoginAddresses()})
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(emailCodeRequestHandler)

	// Note: VerifyEmailCode only consults EmailCode, not UserStore — the allow-list
	// and Enabled gate is enforced at POST /login (a code is only ever issued to an
	// allow-listed, enabled email). UserStore is set only to satisfy the handler shape.
	login := userauth.LoginHandler{UserStore: &emailCodeUsers, EmailCode: emailLoginCodeStore}

	r.Path("/login/verify").Methods(http.MethodGet).HandlerFunc(emailCodeVerifyGetHandler)
	r.Path("/login/verify").Methods(http.MethodPost).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		emailCodeVerifyPostHandler(w, req, &login, sessMgr)
	})

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ud, err := cookieauth.CtxGetUserData(req)
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		rnd.Render(w, req, "protected.tmpl.html", map[string]any{
			"text": fmt.Sprintf("logged in passwordlessly as: %s", ud.UserId),
		})
	}))
	protected.Use(sessMgr.Middleware)

	r.Path("/logout").Handler(logincookie.LogoutHandler(sessMgr, "/"))

	return r
}

func emailCodeVerifyGetHandler(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	pendingEmailLogins.mu.Lock()
	pending, exists := pendingEmailLogins.items[email]
	pendingEmailLogins.mu.Unlock()
	data := map[string]any{"Email": email}
	if exists {
		data["PlainCode"] = pending.plainCode
	}
	rnd.Render(w, r, "emailcode_verify.tmpl.html", data)
}

func emailCodeVerifyPostHandler(w http.ResponseWriter, r *http.Request, login *userauth.LoginHandler, sessMgr *cookieauth.Manager) {
	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))

	renderErr := func(msg string) {
		pendingEmailLogins.mu.Lock()
		pending, exists := pendingEmailLogins.items[email]
		pendingEmailLogins.mu.Unlock()
		data := map[string]any{"Email": email, "Error": msg}
		if exists {
			data["PlainCode"] = pending.plainCode
		}
		rnd.Render(w, r, "emailcode_verify.tmpl.html", data)
	}

	result, err := login.VerifyEmailCode(email, code)
	if err != nil || !result.Authenticated {
		renderErr("Invalid or expired login code.")
		return
	}

	pendingEmailLogins.mu.Lock()
	delete(pendingEmailLogins.items, email)
	pendingEmailLogins.mu.Unlock()

	if err := sessMgr.LoginUser(r, w, email, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/emailcode/protected", http.StatusSeeOther)
}

func emailCodeRequestHandler(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Email is required.",
			"Emails": emailCodeLoginAddresses(),
		})
		return
	}

	user, err := emailCodeUsers.GetUser(email)
	if err != nil || !user.Enabled {
		rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Unknown email. Use one of the demo addresses listed below.",
			"Email":  email,
			"Emails": emailCodeLoginAddresses(),
		})
		return
	}

	code, expiresAt, err := emailLoginCodeSvc.Generate(email)
	if err != nil {
		rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
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
