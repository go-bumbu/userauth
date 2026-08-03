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
		},
	}
}
