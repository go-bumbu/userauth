package examples

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/dbuser"
	"github.com/gorilla/mux"
)

type userRow struct {
	ID      string
	Enabled bool
}

const demoPageSize = 2

type usersAdminApp struct {
	log   *slog.Logger
	users *dbuser.Store
	rnd   *web.Renderer
}

// UsersAdmin returns an http.Handler (a mux.Router) that manages the user-admin UI.
func UsersAdmin(log *slog.Logger, users *dbuser.Store, rnd *web.Renderer) http.Handler {
	a := &usersAdminApp{log: log, users: users, rnd: rnd}
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
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}

	res, err := a.users.List(dbuser.ListOpts{
		Limit:  demoPageSize,
		Offset: (page - 1) * demoPageSize,
	})
	if err != nil {
		a.log.Error("list users", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	rows := make([]userRow, 0, len(res.Users))
	for _, u := range res.Users {
		rows = append(rows, userRow{ID: u.Id, Enabled: u.Enabled})
	}

	totalPages := (res.Total + demoPageSize - 1) / demoPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	a.rnd.Render(w, r, "usermgmt.tmpl.html", map[string]any{
		"Users":      rows,
		"Msg":        msg,
		"Page":       page,
		"TotalPages": totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
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
