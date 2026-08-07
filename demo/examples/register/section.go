package register

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

// Section describes the self-registration examples for the demo index and
// mounts them on the router.
func Section(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) examples.Section {
	return examples.Section{
		ID:    "register",
		Title: "Registration",
		Info: []template.HTML{
			"User self-registration into the shared database user store (in-memory " +
				"SQLite — data resets on every server restart). Registered accounts can " +
				"log in on the Profile tab.",
		},
		Examples: []examples.Example{
			{
				Title: "Username registration",
				Info: []template.HTML{
					"Username-based: supply a login name and password, account is created immediately.",
				},
				Links: []examples.Link{
					{Href: "/register", Text: "/register", Desc: "username registration"},
				},
				Mount: func(r *mux.Router) {
					reg := NewForms(log, users, rnd)
					r.Path("/register").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Password)
					r.Path("/register/email").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.Email)
					r.Path("/register/email/verify").Methods(http.MethodGet, http.MethodPost).HandlerFunc(reg.EmailVerify)
				},
			},
			{
				Title: "Email registration",
				Info: []template.HTML{
					"Email-based: supply an email and password, then verify a 6-digit code shown on " +
						"the next page (simulating email delivery).",
				},
				Links: []examples.Link{
					{Href: "/register/email", Text: "/register/email", Desc: "email registration with verification code"},
				},
				// mounted together with the username form above (shared Forms instance)
			},
			{
				Title: "JSON API (for SPAs)",
				Info: []template.HTML{
					"The same email-verified registration as a JSON API using the " +
						"register/handlers preset (codes are logged to the server console). Try: " +
						`<code>curl -X POST -d '{"username":"you@example.com","password":"secret"}' http://localhost:8085/api/register</code>`,
				},
				Links: []examples.Link{
					{Text: "POST /api/register", Desc: "start registration, issues a verification code"},
					{Text: "POST /api/register/verify", Desc: "confirm the code, creates the account"},
					{Text: "POST /api/register/request-code", Desc: "re-issue the verification code"},
				},
				Mount: func(r *mux.Router) {
					api := NewAPI(log, users)
					r.Path("/api/register").Methods(http.MethodPost).Handler(api.RegisterHandler())
					r.Path("/api/register/verify").Methods(http.MethodPost).Handler(api.VerifyHandler())
					r.Path("/api/register/request-code").Methods(http.MethodPost).Handler(api.RequestCodeHandler())
				},
			},
		},
	}
}
