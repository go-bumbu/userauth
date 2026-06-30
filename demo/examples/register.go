package examples

import (
	"net/http"
	"strings"
	"sync"
	"time"
	"log/slog"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/store"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/dbusers"
	vcmemory "github.com/go-bumbu/userauth/verificationcode/memory"
)

// Register handles user self-registration (password-based and email-code-based).
type Register struct {
	log     *slog.Logger
	users   *dbusers.DbManager
	reg     *store.Registry
	rnd     *web.Renderer
	store   *vcmemory.Store
	codeSvc *userauth.VerificationCodeService
	pending struct {
		mu    sync.Mutex
		items map[string]pendingEmailReg
	}
}

type pendingEmailReg struct {
	password  string
	plainCode string
	expiresAt time.Time
}

// NewRegister creates a Register and initialises its verification-code store.
func NewRegister(log *slog.Logger, users *dbusers.DbManager, reg *store.Registry, rnd *web.Renderer) *Register {
	a := &Register{log: log, users: users, reg: reg, rnd: rnd, store: vcmemory.New()}
	a.codeSvc = &userauth.VerificationCodeService{Store: a.store.Store, CodeLength: 6, Expiry: 10 * time.Minute}
	a.pending.items = make(map[string]pendingEmailReg)
	return a
}

// Password handles GET/POST /register (username+password registration).
func (a *Register) Password(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.rnd.Render(w, r, "register.tmpl.html", nil)
		return
	}

	login := strings.TrimSpace(r.FormValue("login"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if login == "" || password == "" {
		a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
			"Error": "Login and password are required.",
			"Login": login,
		})
		return
	}

	if password != confirm {
		a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
			"Error": "Passwords do not match.",
			"Login": login,
		})
		return
	}

	if err := a.users.Create(login, password); err != nil {
		a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
			"Error": err.Error(),
			"Login": login,
		})
		return
	}

	a.reg.Add(login)
	a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
		"Success": "User \"" + login + "\" registered successfully.",
	})
}

// Email handles GET/POST /register/email (email + password, issues a verification code).
func (a *Register) Email(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.rnd.Render(w, r, "register_email.tmpl.html", nil)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if email == "" || password == "" {
		a.rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Email and password are required.",
			"Email": email,
		})
		return
	}
	if password != confirm {
		a.rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Passwords do not match.",
			"Email": email,
		})
		return
	}

	code, expiresAt, err := a.codeSvc.Generate(email)
	if err != nil {
		a.rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Could not generate verification code.",
			"Email": email,
		})
		return
	}

	a.pending.mu.Lock()
	a.pending.items[email] = pendingEmailReg{password: password, plainCode: code, expiresAt: expiresAt}
	a.pending.mu.Unlock()

	http.Redirect(w, r, "/register/email/verify?email="+email, http.StatusSeeOther)
}

// EmailVerify handles GET/POST /register/email/verify (validates the code and creates the account).
func (a *Register) EmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		a.pending.mu.Lock()
		pending, exists := a.pending.items[email]
		a.pending.mu.Unlock()
		data := map[string]any{"Email": email}
		if exists {
			data["PlainCode"] = pending.plainCode
		}
		a.rnd.Render(w, r, "register_email_verify.tmpl.html", data)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))

	renderErr := func(msg string) {
		a.rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
			"Email": email,
			"Error": msg,
		})
	}

	ok, err := a.store.VerifyEmailCode(email, code)
	if err != nil || !ok {
		renderErr("Invalid or expired verification code.")
		return
	}

	a.pending.mu.Lock()
	pending, exists := a.pending.items[email]
	if exists {
		delete(a.pending.items, email)
	}
	a.pending.mu.Unlock()

	if !exists || time.Now().After(pending.expiresAt) {
		renderErr("Registration session expired. Please start over.")
		return
	}

	if err := a.users.CreateUser(dbusers.User{
		LoginID:              email,
		Pw:                   pending.password,
		Enabled:              true,
		PrimaryEmail:         email,
		PrimaryEmailVerified: true,
	}); err != nil {
		renderErr("Could not create account: " + err.Error())
		return
	}

	a.reg.Add(email)
	a.rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
		"Email":   email,
		"Success": "Account created. You can now log in at /profile/login.",
	})
}
