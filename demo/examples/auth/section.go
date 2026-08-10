package auth

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/gorilla/mux"
)

// Section describes the authentication-method examples for the demo index
// and mounts them on the router.
func Section(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) examples.Section {
	return examples.Section{
		ID:    "auth",
		Title: "Authentication",
		Info: []template.HTML{
			"Every request is authenticated on its own — no login step, no session.",
			"Static users (no database): <i>admin:admin</i> or <i>demo:demo</i>",
		},
		Examples: []examples.Example{
			{
				Title: "Basic Auth",
				Info: []template.HTML{
					"Verifies credentials on every request via the Authorization header.",
				},
				Links: []examples.Link{
					{Href: "/basic/enforce", Text: "/basic/enforce", Desc: "browser prompts for credentials when not authenticated"},
					{Href: "/basic/silent", Text: "/basic/silent", Desc: "returns 401 silently, no browser prompt, if no credentials are provided"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/basic/").Handler(http.StripPrefix("/basic", Basic(log, users, rnd)))
				},
			},
			{
				Title: "HTTP Header",
				Info: []template.HTML{
					"Delegates authentication to an upstream service that sets the X-User-Auth header.",
					`Test with: <code>curl -H "X-User-Auth: demo" http://localhost:8085/header/protected</code>`,
				},
				Links: []examples.Link{
					{Href: "/header/protected", Text: "/header/protected", Desc: "header-protected page"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/header/").Handler(http.StripPrefix("/header", Header(log, rnd)))
				},
			},
			{
				Title: "Cookie session",
				Info: []template.HTML{
					"Authenticates each request from an encrypted session cookie. Shown in " +
						"isolation: /start logs in a fixed demo user without any credential check — " +
						"the login flows show real verification in front of the same session.",
				},
				Links: []examples.Link{
					{Href: "/cookie/start", Text: "/cookie/start", Desc: "start a session (no credential check, demo only)"},
					{Href: "/cookie/protected", Text: "/cookie/protected", Desc: "cookie-protected page"},
					{Href: "/cookie/end", Text: "/cookie/end", Desc: "end the session"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/cookie/").Handler(http.StripPrefix("/cookie", Cookie(log, rnd)))
				},
			},
			{
				Title: "Auth chain",
				Info: []template.HTML{
					"Chains several auth handlers: a cookie session is tried first, then " +
						"basic auth; when both fail the request is redirected to a login " +
						"endpoint instead of answering 401.",
					"Test the basic-auth link with: <code>curl -u demo:demo http://localhost:8085/chain/protected</code>",
				},
				Links: []examples.Link{
					{Href: "/chain/login", Text: "/chain/login", Desc: "start a cookie session (demo only, no credential check)"},
					{Href: "/chain/protected", Text: "/chain/protected", Desc: "chain-protected page (cookie or basic auth)"},
					{Href: "/chain/logout", Text: "/chain/logout", Desc: "end the session"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/chain/").Handler(http.StripPrefix("/chain", Chain(log, users, rnd)))
				},
			},
			{
				Title: "Personal access token",
				Info: []template.HTML{
					"Authenticates requests via PAT token, cookie session, or basic auth — a chain where all methods coexist.",
					`Get a token at <a href="/token/new">/token/new</a>, then: <code>curl -H "Authorization: Bearer &lt;token&gt;" http://localhost:8085/token/protected</code>`,
					"The protected endpoint also accepts cookie session (browsers) and basic auth (demo:demo).",
				},
				Links: []examples.Link{
					{Href: "/token/new", Text: "/token/new", Desc: "mint a demo token for user 'demo' (demo only, no credential check)"},
					{Href: "/token/protected", Text: "/token/protected", Desc: "chain-protected endpoint (token, cookie, or basic auth)"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/token/").Handler(http.StripPrefix("/token", Token(log, users, rnd)))
				},
			},
			{
				Title: "Recoverable token (user+token)",
				Info: []template.HTML{
					"Mints a <i>recoverable</i> PAT: the secret is stored encrypted (AES-GCM via " +
						"<code>SecretCipher</code>) in addition to its hash, so the server can answer " +
						"challenge-style logins where the secret itself never travels on the wire.",
					"The token splits into a virtual username (the token ID) and password (the secret) — " +
						"the protocol used by Subsonic-compatible clients: <code>t = md5(password + salt)</code>. " +
						"The same token still works whole as a Bearer apiKey.",
				},
				Links: []examples.Link{
					{Href: "/rectoken/new", Text: "/rectoken/new", Desc: "mint a recoverable token for user 'demo' (demo only, no credential check)"},
					{Href: "/rectoken/protected", Text: "/rectoken/protected", Desc: "protected endpoint (salted challenge ?u=&t=&s= or Bearer token)"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/rectoken/").Handler(http.StripPrefix("/rectoken", Recoverable(log, users, rnd)))
				},
			},
		},
	}
}
