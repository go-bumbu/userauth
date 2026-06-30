package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/userstore/dbusers"
	"github.com/go-bumbu/userauth/verificationcode/memory"
)

var emailCodeStore = memory.New()
var emailCodeSvc = &userauth.VerificationCodeService{
	Store:      emailCodeStore.Store,
	CodeLength: 6,
	Expiry:     10 * time.Minute,
}

type pendingEmailReg struct {
	password  string
	plainCode string
	expiresAt time.Time
}

var pendingEmailRegs = struct {
	mu    sync.Mutex
	items map[string]pendingEmailReg
}{items: make(map[string]pendingEmailReg)}

func registerEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rnd.Render(w, r, "register_email.tmpl.html", nil)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if email == "" || password == "" {
		rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Email and password are required.",
			"Email": email,
		})
		return
	}
	if password != confirm {
		rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Passwords do not match.",
			"Email": email,
		})
		return
	}

	code, expiresAt, err := emailCodeSvc.Generate(email)
	if err != nil {
		rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": "Could not generate verification code.",
			"Email": email,
		})
		return
	}

	pendingEmailRegs.mu.Lock()
	pendingEmailRegs.items[email] = pendingEmailReg{password: password, plainCode: code, expiresAt: expiresAt}
	pendingEmailRegs.mu.Unlock()

	http.Redirect(w, r, "/register/email/verify?email="+email, http.StatusSeeOther)
}

func registerEmailVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		pendingEmailRegs.mu.Lock()
		pending, exists := pendingEmailRegs.items[email]
		pendingEmailRegs.mu.Unlock()
		data := map[string]any{"Email": email}
		if exists {
			data["PlainCode"] = pending.plainCode
		}
		rnd.Render(w, r, "register_email_verify.tmpl.html", data)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))

	renderErr := func(msg string) {
		rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
			"Email": email,
			"Error": msg,
		})
	}

	ok, err := emailCodeStore.VerifyEmailCode(email, code)
	if err != nil || !ok {
		renderErr("Invalid or expired verification code.")
		return
	}

	pendingEmailRegs.mu.Lock()
	pending, exists := pendingEmailRegs.items[email]
	if exists {
		delete(pendingEmailRegs.items, email)
	}
	pendingEmailRegs.mu.Unlock()

	if !exists || time.Now().After(pending.expiresAt) {
		renderErr("Registration session expired. Please start over.")
		return
	}

	if err := dbUserMgr.CreateUser(dbusers.User{
		LoginID:              email,
		Pw:                   pending.password,
		Enabled:              true,
		PrimaryEmail:         email,
		PrimaryEmailVerified: true,
	}); err != nil {
		renderErr("Could not create account: " + err.Error())
		return
	}

	userIDs = append(userIDs, email)
	rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
		"Email":   email,
		"Success": "Account created. You can now log in at /profile/login.",
	})
}
