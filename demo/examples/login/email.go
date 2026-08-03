package login

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/internal/deliver"
	"github.com/go-bumbu/userauth/demo/web"
	loginflow "github.com/go-bumbu/userauth/flow/login"
	flowmemory "github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// basePath is where the demo router mounts this example. Redirects must include
// it because the mux StripPrefix has already removed it from the request path,
// so a relative redirect would resolve against the wrong base.
const basePath = "/emailcode"

// emailLoginApp holds the demo-owned transport: forms, redirects and
// rendering. The login flow itself — issue code, anti-enumeration, verify,
// session — lives in loginflow.Flow.
type emailLoginApp struct {
	rnd   *web.Renderer
	users staticusers.Users
	flow  *loginflow.Flow
	board *deliver.Board
}

// Email demonstrates passwordless email-code login persisted in a cookie
// session, built on loginflow with a single-factor email policy. The demo
// supplies a Deliverer that shows the code on the verify page instead of
// emailing it.
func Email(log *slog.Logger, rnd *web.Renderer) http.Handler {
	users := staticusers.Users{Users: []staticusers.User{
		{Id: "admin@example.com", Enabled: true},
		{Id: "demo@example.com", Enabled: true},
	}}

	codes := verificationcode.NewService(csmemory.New(), verificationcode.Opts{
		CodeLength: 6,
		Expiry:     10 * time.Minute,
	})

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("emailcode: cookie store: %w", err))
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
		panic(fmt.Errorf("emailcode: session manager: %w", err))
	}

	app := &emailLoginApp{
		rnd:   rnd,
		users: users,
		board: deliver.NewBoard(),
	}
	app.flow = &loginflow.Flow{
		Users: &app.users,
		Methods: []loginflow.Method{
			// a real deployment would wire an SMTP deliverer instead of the board
			loginflow.EmailCodeMethod(codes, app.board),
		},
		Policy:   loginflow.RequireAny(loginflow.Chain{loginflow.MethodEmail}),
		Attempts: flowmemory.New(),
		Session:  sessMgr,
		Logger:   log,
	}

	r := mux.NewRouter()
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(app.loginForm)
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(app.requestCode)
	r.Path("/login/verify").Methods(http.MethodGet).HandlerFunc(app.verifyForm)
	r.Path("/login/verify").Methods(http.MethodPost).HandlerFunc(app.verifyCode)

	protected := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	protected.Handle("", http.HandlerFunc(app.protected))
	protected.Use(sessMgr.Middleware)

	r.Path("/logout").Handler(cookieauth.LogoutHandler(sessMgr, "/"))
	return r
}

// loginForm shows the email-entry form.
func (a *emailLoginApp) loginForm(w http.ResponseWriter, r *http.Request) {
	a.renderLogin(w, r, "", "")
}

// requestCode asks the flow to issue a one-time code and redirects to the
// verify page. Initiate is enumeration-safe: for unknown or disabled emails it
// silently does nothing, so the redirect is identical either way.
func (a *emailLoginApp) requestCode(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		a.renderLogin(w, r, "", "Email is required.")
		return
	}
	if err := a.flow.Initiate(r, email, loginflow.MethodEmail); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, basePath+"/login/verify?email="+url.QueryEscape(email), http.StatusSeeOther)
}

// verifyForm shows the code-entry form (and, for demo convenience, the plain code).
func (a *emailLoginApp) verifyForm(w http.ResponseWriter, r *http.Request) {
	a.renderVerify(w, r, strings.TrimSpace(r.URL.Query().Get("email")), "")
}

// verifyCode submits the code as the email factor; the flow creates the
// session when the policy is satisfied.
func (a *emailLoginApp) verifyCode(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))
	if email == "" || code == "" {
		a.renderVerify(w, r, email, "Email and code are required.")
		return
	}

	res, err := a.flow.Submit(r, w, email, loginflow.MethodEmail, code, false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !res.Done {
		a.renderVerify(w, r, email, "Invalid or expired login code.")
		return
	}
	a.board.Clear(email)
	http.Redirect(w, r, basePath+"/protected", http.StatusSeeOther)
}

// protected renders the page shown only to an authenticated session.
func (a *emailLoginApp) protected(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.rnd.Render(w, r, "protected.tmpl.html", map[string]any{
		"text": fmt.Sprintf("logged in passwordlessly as: %s", ud.UserId),
	})
}

// renderLogin renders the login form with the allow-listed addresses and an optional error.
func (a *emailLoginApp) renderLogin(w http.ResponseWriter, r *http.Request, email, errMsg string) {
	a.rnd.Render(w, r, "emailcode_login.tmpl.html", map[string]any{
		"Emails": a.addresses(),
		"Email":  email,
		"Error":  errMsg,
	})
}

// renderVerify renders the code-entry form, showing the stashed plaintext code
// (the demo cannot actually email it) plus an optional error.
func (a *emailLoginApp) renderVerify(w http.ResponseWriter, r *http.Request, email, errMsg string) {
	data := map[string]any{"Email": email}
	if code, ok := a.board.Lookup(email); ok {
		data["PlainCode"] = code
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	a.rnd.Render(w, r, "emailcode_verify.tmpl.html", data)
}

// addresses returns the demo's allow-listed email addresses, shown in the login form.
func (a *emailLoginApp) addresses() []string {
	addrs := make([]string, 0, len(a.users.Users))
	for _, u := range a.users.Users {
		addrs = append(addrs, u.Id)
	}
	return addrs
}
