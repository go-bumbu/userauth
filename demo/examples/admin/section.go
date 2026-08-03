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
		},
	}
}
