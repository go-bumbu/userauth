package main

import (
	"crypto/rand"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/userstore/dbusers"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var dbUserMgr *dbusers.DbManager
var userIDs []string

func init() {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to open in-memory sqlite: " + err.Error())
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		panic("failed to generate TOTP encryption key: " + err.Error())
	}
	mgr, err := dbusers.NewDbManager(db, dbusers.ManagerOpts{
		BcryptDifficulty:  4,
		DefaultEnabled:    true,
		TOTPEncryptionKey: totpKey,
	})
	if err != nil {
		panic("failed to create db manager: " + err.Error())
	}
	dbUserMgr = mgr

	for _, seed := range []struct{ id, pw string }{
		{"admin", "admin"},
		{"demo", "demo"},
		{"admin@example.com", "admin"},
		{"demo@example.com", "demo"},
	} {
		if err := dbUserMgr.Create(seed.id, seed.pw); err != nil {
			panic("failed to seed user " + seed.id + ": " + err.Error())
		}
		userIDs = append(userIDs, seed.id)
	}
}

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
	rows := make([]userRow, 0, len(userIDs))
	for _, id := range userIDs {
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
	userIDs = append(userIDs, login)
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
