// Package admin holds the demo example for admin user management on
// userdb.Store: a paginated user list plus create and enable/disable actions.
package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
)

// userRow is the per-user view model rendered in the admin table: the login
// ID is what admins recognize, the canonical ID is what actions target.
type userRow struct {
	ID      string
	LoginID string
	Enabled bool
}

// demoPageSize is deliberately tiny so the pagination controls are exercised
// by just the handful of seeded demo accounts.
const demoPageSize = 2

type usersAdminApp struct {
	log   *slog.Logger
	users *userdb.Store
	rnd   *web.Renderer
}

// New returns an http.Handler (a mux.Router) that manages the user-admin UI.
func New(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) http.Handler {
	a := &usersAdminApp{log: log, users: users, rnd: rnd}
	r := mux.NewRouter()
	r.Path("/").Methods(http.MethodGet).HandlerFunc(a.list)
	r.Path("/").Methods(http.MethodPost).HandlerFunc(a.create)
	r.Path("/{id}/enable").Methods(http.MethodPost).HandlerFunc(a.enable)
	r.Path("/{id}/disable").Methods(http.MethodPost).HandlerFunc(a.disable)
	return r
}

// list renders the user table for the requested page.
func (a *usersAdminApp) list(w http.ResponseWriter, r *http.Request) {
	a.listWithMsg(w, r, "")
}

// listWithMsg renders one page of users (selected by the ?page= query) plus an
// optional banner message. It pages through Store.List and derives the
// navigation state from the store's total user count.
func (a *usersAdminApp) listWithMsg(w http.ResponseWriter, r *http.Request, msg string) {
	// ?page= is 1-based; anything absent, non-numeric, or < 1 falls back to page 1.
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}

	res, err := a.users.List(userdb.ListOpts{
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
		rows = append(rows, userRow{ID: u.ID, LoginID: u.LoginID, Enabled: u.Enabled})
	}

	// ceil(total / pageSize), floored at 1 so an empty store still reads "page 1 of 1".
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

// create adds a user from the submitted form, re-rendering the list with an
// error banner on failure (e.g. a duplicate login) and redirecting on success.
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
	http.Redirect(w, r, "/useradmin/", http.StatusSeeOther)
}

// enable activates the user account named in the URL.
func (a *usersAdminApp) enable(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.users.SetEnabled(id, true); err != nil {
		a.log.Error("enable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/useradmin/", http.StatusSeeOther)
}

// disable deactivates the user account named in the URL.
func (a *usersAdminApp) disable(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.users.SetEnabled(id, false); err != nil {
		a.log.Error("disable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/useradmin/", http.StatusSeeOther)
}
