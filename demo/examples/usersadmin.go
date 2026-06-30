package examples

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/demo/store"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/dbuser"
	"github.com/gorilla/mux"
)

type userRow struct {
	ID      string
	Enabled bool
}

type usersAdminApp struct {
	log   *slog.Logger
	users *dbuser.Store
	reg   *store.Registry
	rnd   *web.Renderer
}

// UsersAdmin returns an http.Handler (a mux.Router) that manages the user-admin UI.
func UsersAdmin(log *slog.Logger, users *dbuser.Store, reg *store.Registry, rnd *web.Renderer) http.Handler {
	a := &usersAdminApp{log: log, users: users, reg: reg, rnd: rnd}
	r := mux.NewRouter()
	r.Path("/").Methods(http.MethodGet).HandlerFunc(a.list)
	r.Path("/").Methods(http.MethodPost).HandlerFunc(a.create)
	r.Path("/{id}/enable").Methods(http.MethodPost).HandlerFunc(a.enable)
	r.Path("/{id}/disable").Methods(http.MethodPost).HandlerFunc(a.disable)
	return r
}

func (a *usersAdminApp) list(w http.ResponseWriter, r *http.Request) {
	a.listWithMsg(w, r, "")
}

func (a *usersAdminApp) listWithMsg(w http.ResponseWriter, r *http.Request, msg string) {
	ids := a.reg.List()
	rows := make([]userRow, 0, len(ids))
	for _, id := range ids {
		u, err := a.users.GetUser(id)
		if err != nil {
			rows = append(rows, userRow{ID: id, Enabled: false})
			continue
		}
		rows = append(rows, userRow{ID: u.Id, Enabled: u.Enabled})
	}
	a.rnd.Render(w, r, "usermgmt.tmpl.html", map[string]any{
		"Users": rows,
		"Msg":   msg,
	})
}

func (a *usersAdminApp) create(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if strings.TrimSpace(login) == "" || strings.TrimSpace(password) == "" {
		a.listWithMsg(w, r, "Error: login and password are required")
		return
	}
	if err := a.users.Create(login, password); err != nil {
		a.listWithMsg(w, r, "Error: "+err.Error())
		return
	}
	a.reg.Add(login)
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}

func (a *usersAdminApp) enable(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.users.SetEnabled(id, true); err != nil {
		a.log.Error("enable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}

func (a *usersAdminApp) disable(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.users.SetEnabled(id, false); err != nil {
		a.log.Error("disable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}
