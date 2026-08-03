package login

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/web"
	loginflow "github.com/go-bumbu/userauth/flow/login"
	flowmemory "github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// totpBasePath is where the demo router mounts this example; see basePath for
// why redirects must include it.
const totpBasePath = "/totp"

// demoTOTPSecret is the fixed base32 TOTP secret of the demo account. A real
// deployment generates one per user at enrolment (see the profile example);
// the demo fixes it so the verify page can play the authenticator app.
const demoTOTPSecret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- demo TOTP secret

// totpLoginApp holds the demo-owned transport: forms, redirects and rendering.
type totpLoginApp struct {
	rnd  *web.Renderer
	flow *loginflow.Flow
}

// TOTP demonstrates a two-step login: the policy requires the password first
// and an authenticator code second, on every login. The verify page shows the
// currently valid code (simulating the user's authenticator app).
func TOTP(log *slog.Logger, rnd *web.Renderer) http.Handler {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "demo", HashPw: mustHashPw("demo"), Enabled: true, TOTPSecret: demoTOTPSecret},
	}}

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("totp: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_totp_demo_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("totp: session manager: %w", err))
	}

	app := &totpLoginApp{rnd: rnd}
	app.flow = &loginflow.Flow{
		Users: users,
		Methods: []loginflow.Method{
			loginflow.PasswordMethod{Users: users},
			loginflow.TOTPMethod{TOTP: users},
		},
		Policy:   loginflow.RequireAny(loginflow.Chain{loginflow.MethodPassword, loginflow.MethodTOTP}),
		Attempts: flowmemory.New(),
		Session:  sessMgr,
		Logger:   log,
	}

	r := mux.NewRouter()
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(app.loginForm)
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(app.passwordStep)
	r.Path("/login/verify").Methods(http.MethodGet).HandlerFunc(app.verifyForm)
	r.Path("/login/verify").Methods(http.MethodPost).HandlerFunc(app.verifyCode)

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", rnd.ProtectedPage("content protected by password + TOTP login"))
	protected.Use(sessMgr.Middleware)

	r.Path("/logout").Handler(cookieauth.LogoutHandler(sessMgr, "/"))
	return r
}

// loginForm shows the username+password form (step 1 of 2).
func (a *totpLoginApp) loginForm(w http.ResponseWriter, r *http.Request) {
	a.rnd.Render(w, r, "totp_login.tmpl.html", nil)
}

// passwordStep submits the password factor; on success the policy demands the
// TOTP factor next, so the user is redirected to the verify page.
func (a *totpLoginApp) passwordStep(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	res, err := a.flow.Submit(r, w, username, loginflow.MethodPassword, r.FormValue("password"), false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		a.rnd.Render(w, r, "totp_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
		return
	}
	if res.Done { // cannot happen with this policy; kept for safety
		http.Redirect(w, r, totpBasePath+"/protected", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, totpBasePath+"/login/verify?user="+url.QueryEscape(username), http.StatusSeeOther)
}

// verifyForm shows the code-entry form (and, playing the authenticator app,
// the currently valid code — refresh after 30s for a fresh one).
func (a *totpLoginApp) verifyForm(w http.ResponseWriter, r *http.Request) {
	a.renderVerify(w, r, strings.TrimSpace(r.URL.Query().Get("user")), "")
}

// verifyCode submits the code as the TOTP factor; the flow creates the
// session when the policy is satisfied.
func (a *totpLoginApp) verifyCode(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	code := strings.TrimSpace(r.FormValue("code"))

	res, err := a.flow.Submit(r, w, username, loginflow.MethodTOTP, code, false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !res.Done {
		// wrong code, or the pending attempt expired and the password step
		// must be repeated — the start-over link below the form covers that
		a.renderVerify(w, r, username, "Invalid code, try again.")
		return
	}
	http.Redirect(w, r, totpBasePath+"/protected", http.StatusSeeOther)
}

// renderVerify renders the code-entry form with the current code and an optional error.
func (a *totpLoginApp) renderVerify(w http.ResponseWriter, r *http.Request, username, errMsg string) {
	code, err := totp.GenerateCode(demoTOTPSecret, time.Now())
	if err != nil {
		code = ""
	}
	data := map[string]any{
		"Username":    username,
		"CurrentCode": code,
		"Secret":      demoTOTPSecret,
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	a.rnd.Render(w, r, "totp_verify.tmpl.html", data)
}

// mustHashPw bcrypt-hashes a demo password for the examples that embed their
// own static user; the static store holds hashes only.
func mustHashPw(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}
