package login

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/web"
	loginflow "github.com/go-bumbu/userauth/flow/login"
	flowmemory "github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// recoveryBasePath is where the demo router mounts this example; see basePath
// for why redirects must include it.
const recoveryBasePath = "/recovery"

// recoveryStore adds single-use recovery codes to the static user store,
// implementing userauth.RecoveryCodeVerifier for loginflow.RecoveryMethod.
// The demo keeps the codes in plaintext so it can display them; a real store
// keeps only hashes (see userstore/userdb and the profile example).
type recoveryStore struct {
	staticusers.Users
	mu    sync.Mutex
	codes map[string][]string // userID -> remaining (unused) codes
}

// VerifyRecoveryCode consumes a matching code: recovery codes are single-use.
func (s *recoveryStore) VerifyRecoveryCode(userID, code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.codes[userID] {
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			s.codes[userID] = slices.Delete(s.codes[userID], i, i+1)
			return true, nil
		}
	}
	return false, nil
}

// Remaining returns a copy of the user's unused codes, for display.
func (s *recoveryStore) Remaining(userID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.codes[userID])
}

// recoveryLoginApp holds the demo-owned transport: forms, redirects and rendering.
type recoveryLoginApp struct {
	rnd   *web.Renderer
	users *recoveryStore
	flow  *loginflow.Flow
}

// Recovery demonstrates completing a two-factor login with a single-use
// recovery code instead of the authenticator: the scenario where the user has
// lost their device. The policy requires the password first and a recovery
// code second; each code is consumed on use.
func Recovery(log *slog.Logger, rnd *web.Renderer) http.Handler {
	users := &recoveryStore{
		Users: staticusers.Users{Users: []staticusers.User{
			{Id: "demo", HashPw: userauth.MustHashPassword("demo"), Enabled: true},
		}},
		codes: map[string][]string{
			"demo": {"tqxm3k9d", "p7wf2rna", "z4hcy8sb"},
		},
	}

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("recovery: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_recovery_demo_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("recovery: session manager: %w", err))
	}

	app := &recoveryLoginApp{rnd: rnd, users: users}
	app.flow = &loginflow.Flow{
		Users: users,
		Methods: []loginflow.Method{
			loginflow.PasswordMethod{Users: users},
			loginflow.RecoveryMethod{Codes: users},
		},
		Policy:   loginflow.RequireAny(loginflow.Chain{loginflow.MethodPassword, loginflow.MethodRecovery}),
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
	protected.Handle("", rnd.ProtectedPage("content protected by password + recovery-code login"))
	protected.Use(sessMgr.Middleware)

	r.Path("/logout").Handler(cookieauth.LogoutHandler(sessMgr, "/"))
	return r
}

// loginForm shows the username+password form (step 1 of 2).
func (a *recoveryLoginApp) loginForm(w http.ResponseWriter, r *http.Request) {
	a.rnd.Render(w, r, "recovery_login.tmpl.html", nil)
}

// passwordStep submits the password factor; on success the policy demands a
// recovery code next, so the user is redirected to the verify page.
func (a *recoveryLoginApp) passwordStep(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	res, err := a.flow.Submit(r, w, username, loginflow.MethodPassword, r.FormValue("password"), false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		a.rnd.Render(w, r, "recovery_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
		return
	}
	if res.Done { // cannot happen with this policy; kept for safety
		http.Redirect(w, r, recoveryBasePath+"/protected", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, recoveryBasePath+"/login/verify?user="+url.QueryEscape(username), http.StatusSeeOther)
}

// verifyForm shows the recovery-code form together with the user's remaining
// codes (playing the safe place the user wrote them down in).
func (a *recoveryLoginApp) verifyForm(w http.ResponseWriter, r *http.Request) {
	a.renderVerify(w, r, strings.TrimSpace(r.URL.Query().Get("user")), "")
}

// verifyCode submits the code as the recovery factor; the flow consumes the
// code and creates the session when the policy is satisfied.
func (a *recoveryLoginApp) verifyCode(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	code := strings.TrimSpace(r.FormValue("code"))

	res, err := a.flow.Submit(r, w, username, loginflow.MethodRecovery, code, false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !res.Done {
		// wrong or already-used code, or the pending attempt expired and the
		// password step must be repeated — the start-over link covers that
		a.renderVerify(w, r, username, "Invalid or already used recovery code.")
		return
	}
	http.Redirect(w, r, recoveryBasePath+"/protected", http.StatusSeeOther)
}

// renderVerify renders the code-entry form with the remaining codes and an optional error.
func (a *recoveryLoginApp) renderVerify(w http.ResponseWriter, r *http.Request, username, errMsg string) {
	data := map[string]any{
		"Username": username,
		"Codes":    a.users.Remaining(username),
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	a.rnd.Render(w, r, "recovery_verify.tmpl.html", data)
}
