package login

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

// Section describes the login-flow examples for the demo index and mounts
// them on the router.
func Section(log *slog.Logger, static userauth.UserGetter, users *userdb.Store, rnd *web.Renderer) examples.Section {
	return examples.Section{
		ID:    "login",
		Title: "Login flows",
		Info: []template.HTML{
			"Credentials are verified once and an encrypted cookie session is established; " +
				"protected pages check that cookie.",
			"Static users (no database): <i>admin:admin</i> or <i>demo:demo</i>",
		},
		Examples: []examples.Example{
			{
				Title: "Password",
				Info: []template.HTML{
					"Log in with a username and password.",
				},
				Links: []examples.Link{
					{Href: "/password/login", Text: "/password/login", Desc: "login form"},
					{Href: "/password/protected", Text: "/password/protected", Desc: "session-protected page"},
					{Href: "/password/logout", Text: "/password/logout", Desc: "logout (invalidate the session cookie)"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/password/").Handler(http.StripPrefix("/password", Password(log, static, rnd)))
				},
			},
			{
				Title: "Passwordless (email code)",
				Info: []template.HTML{
					"Log in with just an email — a 6-digit code is shown on the next page " +
						"(simulating email delivery). No password. Demo accounts: " +
						"<code>admin@example.com</code>, <code>demo@example.com</code>.",
				},
				Links: []examples.Link{
					{Href: "/emailcode/login", Text: "/emailcode/login", Desc: "request a login code"},
					{Href: "/emailcode/protected", Text: "/emailcode/protected", Desc: "cookie-protected page"},
					{Href: "/emailcode/logout", Text: "/emailcode/logout", Desc: "logout"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/emailcode/").Handler(http.StripPrefix("/emailcode", Email(log, rnd)))
				},
			},
			{
				Title: "Password + TOTP",
				Info: []template.HTML{
					"A two-step login: password first, then a 6-digit authenticator code, " +
						"required on every login (<code>RequireAny(Chain{password, totp})</code>). " +
						"The verify page shows the currently valid code, simulating the " +
						"authenticator app. Demo account: <code>demo:demo</code>.",
				},
				Links: []examples.Link{
					{Href: "/totp/login", Text: "/totp/login", Desc: "password step, then the authenticator-code step"},
					{Href: "/totp/protected", Text: "/totp/protected", Desc: "session-protected page"},
					{Href: "/totp/logout", Text: "/totp/logout", Desc: "logout"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/totp/").Handler(http.StripPrefix("/totp", TOTP(log, rnd)))
				},
			},
			{
				Title: "Recovery code",
				Info: []template.HTML{
					"The lost-authenticator path: the second factor is completed with a " +
						"single-use recovery code (<code>login.RecoveryMethod</code>) instead of " +
						"a TOTP code. The verify page lists the remaining codes; each works " +
						"exactly once. Demo account: <code>demo:demo</code>.",
				},
				Links: []examples.Link{
					{Href: "/recovery/login", Text: "/recovery/login", Desc: "password step, then the recovery-code step"},
					{Href: "/recovery/protected", Text: "/recovery/protected", Desc: "session-protected page"},
					{Href: "/recovery/logout", Text: "/recovery/logout", Desc: "logout"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/recovery/").Handler(http.StripPrefix("/recovery", Recovery(log, rnd)))
				},
			},
			{
				Title: "JSON API (for SPAs)",
				Info: []template.HTML{
					"The same password (+ optional TOTP) login as JSON endpoints, using the " +
						"login/handlers preset over the database accounts. Try: " +
						`<code>curl -X POST -d '{"username":"demo@example.com","password":"demo"}' http://localhost:8085/api/login</code>`,
				},
				Links: []examples.Link{
					{Text: "POST /api/login", Desc: "password step"},
					{Text: "POST /api/login/verify", Desc: "second factor (totp / recovery)"},
				},
				Mount: func(r *mux.Router) {
					api := API(log, users)
					r.Path("/api/login").Methods(http.MethodPost).Handler(api.LoginHandler())
					r.Path("/api/login/verify").Methods(http.MethodPost).Handler(api.VerifyHandler())
				},
			},
		},
	}
}
