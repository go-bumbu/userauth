package profile

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

// Section describes the profile self-service example for the demo index and
// mounts it on the router.
func Section(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) examples.Section {
	return examples.Section{
		ID:    "profile",
		Title: "Profile",
		Info: []template.HTML{
			"An authenticated self-service area backed by the database user store " +
				"(in-memory SQLite — data resets on every server restart).",
		},
		Examples: []examples.Example{
			{
				Title: "My Profile",
				Info: []template.HTML{
					"Logged-in users can view their account details, change their password, and update their email. " +
						"Pre-populated accounts: <code>admin@example.com</code> / <code>admin</code> and " +
						"<code>demo@example.com</code> / <code>demo</code> — or register your own on the Registration tab. " +
						"Accounts can also enable a TOTP authenticator as a second factor (with one-time recovery codes).",
				},
				Links: []examples.Link{
					{Href: "/profile/", Text: "/profile/", Desc: "view and edit your profile (redirects to login if not authenticated)"},
					{Href: "/profile/login", Text: "/profile/login", Desc: "login with a database account (asks for TOTP when enrolled)"},
					{Href: "/profile/logout", Text: "/profile/logout", Desc: "logout"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/profile/").Handler(http.StripPrefix("/profile", New(log, users, rnd)))
				},
			},
		},
	}
}
