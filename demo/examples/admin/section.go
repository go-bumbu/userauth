package admin

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

// Section describes the admin user-management example for the demo index and
// mounts it on the router.
func Section(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) examples.Section {
	return examples.Section{
		ID:    "admin",
		Title: "User admin",
		Info: []template.HTML{
			"Admin user management on the database user store (in-memory SQLite — " +
				"data resets on every server restart).",
		},
		Examples: []examples.Example{
			{
				Title: "User management",
				Info: []template.HTML{
					"Paginated user list; create users and toggle their enabled state.",
				},
				Links: []examples.Link{
					{Href: "/useradmin/", Text: "/useradmin/", Desc: "list, create, enable/disable users"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/useradmin/").Handler(http.StripPrefix("/useradmin", New(log, users, rnd)))
				},
			},
			{
				Title: "Initial admin bootstrap",
				Info: []template.HTML{
					"Solves the chicken-and-egg problem of the first admin account: " +
						"<code>Store.Bootstrap</code> seeds the initial admin only while the store " +
						"is completely empty, so re-running it on every startup is safe and a " +
						"deleted admin is never resurrected by stale configuration. Uses its own " +
						"empty store, separate from the other examples.",
				},
				Links: []examples.Link{
					{Href: "/bootstrap/", Text: "/bootstrap/", Desc: "bootstrap, delete and re-create users"},
					{Href: "/bootstrap/status", Text: "/bootstrap/status", Desc: "first-run setup check for SPAs"},
				},
				Mount: func(r *mux.Router) {
					r.PathPrefix("/bootstrap/").Handler(http.StripPrefix("/bootstrap", NewBootstrap(log, rnd)))
				},
			},
		},
	}
}
