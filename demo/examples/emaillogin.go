package examples

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	vcmemory "github.com/go-bumbu/userauth/verificationcode/memory"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

type emailLoginApp struct {
	rnd     *web.Renderer
	users   staticusers.Users
	store   *vcmemory.Store
	codeSvc *userauth.VerificationCodeService
	login   userauth.LoginHandler
	sessMgr *cookieauth.Manager
	pending struct {
		mu    sync.Mutex
		items map[string]pendingEmailLogin
	}
}

type pendingEmailLogin struct {
	plainCode string
	expiresAt time.Time
}

// EmailLogin demonstrates passwordless email-code login persisted in a cookie session.
func EmailLogin(log *slog.Logger, rnd *web.Renderer) http.Handler {
	app := &emailLoginApp{
		rnd: rnd,
	}

	app.users = staticusers.Users{Users: []staticusers.User{
		{Id: "admin@example.com", Enabled: true},
		{Id: "demo@example.com", Enabled: true},
	}}

	app.store = vcmemory.New()
	app.codeSvc = &userauth.VerificationCodeService{
		Store:      app.store.Store,
		CodeLength: 6,
		Expiry:     10 * time.Minute,
	}

	app.pending.items = make(map[string]pendingEmailLogin)

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
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("emailcode: error instantiating session manager: %v", err))
	}
	app.sessMgr = sessMgr

	// Note: VerifyEmailCode only consults EmailCode, not UserStore — the allow-list
	// and Enabled gate is enforced at POST /login (a code is only ever issued to an
	// allow-listed, enabled email). UserStore is set only to satisfy the handler shape.
	app.login = userauth.LoginHandler{UserStore: &app.users, EmailCode: app.store}

	r := mux.NewRouter()

	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		app.rnd.Render(w, req, "emailcode_login.tmpl.html", map[string]any{"Emails": app.addresses()})
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(app.request)

	r.Path("/login/verify").Methods(http.MethodGet).HandlerFunc(app.verifyGet)
	r.Path("/login/verify").Methods(http.MethodPost).HandlerFunc(app.verifyPost)

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ud, err := cookieauth.CtxGetUserData(req)
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		app.rnd.Render(w, req, "protected.tmpl.html", map[string]any{
			"text": fmt.Sprintf("logged in passwordlessly as: %s", ud.UserId),
		})
	}))
	protected.Use(app.sessMgr.Middleware)

	r.Path("/logout").Handler(logincookie.LogoutHandler(app.sessMgr, "/"))

	return r
}

func (a *emailLoginApp) addresses() []string {
	addrs := make([]string, 0, len(a.users.Users))
	for _, u := range a.users.Users {
		addrs = append(addrs, u.Id)
	}
	return addrs
}

func (a *emailLoginApp) request(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		a.rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Email is required.",
			"Emails": a.addresses(),
		})
		return
	}

	user, err := a.users.GetUser(email)
	if err != nil || !user.Enabled {
		a.rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Unknown email. Use one of the demo addresses listed below.",
			"Email":  email,
			"Emails": a.addresses(),
		})
		return
	}

	code, expiresAt, err := a.codeSvc.Generate(email)
	if err != nil {
		a.rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
			"Error":  "Could not generate login code.",
			"Email":  email,
			"Emails": a.addresses(),
		})
		return
	}

	a.pending.mu.Lock()
	a.pending.items[email] = pendingEmailLogin{plainCode: code, expiresAt: expiresAt}
	a.pending.mu.Unlock()

	http.Redirect(w, r, "/emailcode/login/verify?email="+url.QueryEscape(email), http.StatusSeeOther)
}

func (a *emailLoginApp) verifyGet(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	a.pending.mu.Lock()
	pending, exists := a.pending.items[email]
	a.pending.mu.Unlock()
	data := map[string]any{"Email": email}
	if exists {
		data["PlainCode"] = pending.plainCode
	}
	a.rnd.Render(w, r, "emailcode_verify.tmpl.html", data)
}

func (a *emailLoginApp) verifyPost(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))

	renderErr := func(msg string) {
		a.pending.mu.Lock()
		pending, exists := a.pending.items[email]
		a.pending.mu.Unlock()
		data := map[string]any{"Email": email, "Error": msg}
		if exists {
			data["PlainCode"] = pending.plainCode
		}
		a.rnd.Render(w, r, "emailcode_verify.tmpl.html", data)
	}

	result, err := a.login.VerifyEmailCode(email, code)
	if err != nil || !result.Authenticated {
		renderErr("Invalid or expired login code.")
		return
	}

	a.pending.mu.Lock()
	delete(a.pending.items, email)
	a.pending.mu.Unlock()

	if err := a.sessMgr.LoginUser(r, w, email, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/emailcode/protected", http.StatusSeeOther)
}
