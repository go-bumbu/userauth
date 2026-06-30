package main

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type userRow struct {
	ID      string
	Enabled bool
}

func userMgmtDemo() http.Handler {
	r := mux.NewRouter()
	r.Path("/").Methods(http.MethodGet).HandlerFunc(usersListHandler)
	r.Path("/").Methods(http.MethodPost).HandlerFunc(usersCreateHandler)
	r.Path("/{id}/enable").Methods(http.MethodPost).HandlerFunc(usersEnableHandler)
	r.Path("/{id}/disable").Methods(http.MethodPost).HandlerFunc(usersDisableHandler)
	return r
}

func usersListHandler(w http.ResponseWriter, r *http.Request) {
	usersListWithMsg(w, r, "")
}

func usersListWithMsg(w http.ResponseWriter, r *http.Request, msg string) {
	ids := userRegistry.List()
	rows := make([]userRow, 0, len(ids))
	for _, id := range ids {
		u, err := dbUserMgr.GetUser(id)
		if err != nil {
			rows = append(rows, userRow{ID: id, Enabled: false})
			continue
		}
		rows = append(rows, userRow{ID: u.Id, Enabled: u.Enabled})
	}
	rnd.Render(w, r, "usermgmt.tmpl.html", map[string]any{
		"Users": rows,
		"Msg":   msg,
	})
}

func usersCreateHandler(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if strings.TrimSpace(login) == "" || strings.TrimSpace(password) == "" {
		usersListWithMsg(w, r, "Error: login and password are required")
		return
	}
	if err := dbUserMgr.Create(login, password); err != nil {
		usersListWithMsg(w, r, "Error: "+err.Error())
		return
	}
	userRegistry.Add(login)
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}

func usersEnableHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := dbUserMgr.SetEnabled(id, true); err != nil {
		logger.Error("enable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}

func usersDisableHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := dbUserMgr.SetEnabled(id, false); err != nil {
		logger.Error("disable user", "id", id, "err", err)
	}
	http.Redirect(w, r, "/users/", http.StatusSeeOther)
}
