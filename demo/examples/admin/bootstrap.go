package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// bootstrapAdmin is the initial admin this example provisions in code. A real
// application would read the login and a bcrypt hash (User.PwIsHashed) from
// its configuration instead of hardcoding plaintext.
var bootstrapAdmin = userdb.User{LoginID: "admin", Pw: "admin", Enabled: true}

type bootstrapApp struct {
	log   *slog.Logger
	users *userdb.Store
	rnd   *web.Renderer
}

// NewBootstrap returns the initial-admin provisioning example. It creates its
// own empty user store and runs Store.Bootstrap once — the same call an
// application would make on every startup: it seeds the initial admin only
// while the store has no users at all, so deleted accounts are never
// resurrected by stale configuration.
func NewBootstrap(log *slog.Logger, rnd *web.Renderer) http.Handler {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic(fmt.Errorf("bootstrap demo: open in-memory sqlite: %w", err))
	}
	users, err := userdb.New(db, userdb.Opts{BcryptDifficulty: 4, DefaultEnabled: true})
	if err != nil {
		panic(fmt.Errorf("bootstrap demo: create db store: %w", err))
	}
	// what an application does at startup
	if _, err := users.Bootstrap(bootstrapAdmin); err != nil {
		panic(fmt.Errorf("bootstrap demo: bootstrap admin: %w", err))
	}

	a := &bootstrapApp{log: log, users: users, rnd: rnd}
	r := mux.NewRouter()
	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.page(w, req, "")
	})
	r.Path("/").Methods(http.MethodPost).HandlerFunc(a.create)
	r.Path("/run").Methods(http.MethodPost).HandlerFunc(a.run)
	r.Path("/status").Methods(http.MethodGet).HandlerFunc(a.status)
	r.Path("/{id}/delete").Methods(http.MethodPost).HandlerFunc(a.delete)
	return r
}

// page renders the user list plus an optional banner message.
func (a *bootstrapApp) page(w http.ResponseWriter, r *http.Request, msg string) {
	res, err := a.users.List(userdb.ListOpts{})
	if err != nil {
		a.log.Error("bootstrap demo: list users", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rows := make([]userRow, 0, len(res.Users))
	for _, u := range res.Users {
		rows = append(rows, userRow{ID: u.Id, Enabled: u.Enabled})
	}
	a.rnd.Render(w, r, "bootstrap.tmpl.html", map[string]any{
		"Users": rows,
		"Msg":   msg,
	})
}

// run re-executes the startup bootstrap call, showing whether it seeded the
// store or was a no-op because users already exist.
func (a *bootstrapApp) run(w http.ResponseWriter, r *http.Request) {
	seeded, err := a.users.Bootstrap(bootstrapAdmin)
	if err != nil {
		a.page(w, r, "Error: "+err.Error())
		return
	}
	if seeded {
		a.page(w, r, "Bootstrap seeded the store with the initial admin.")
		return
	}
	a.page(w, r, "Bootstrap was a no-op: the store already has users.")
}

// create adds a user, e.g. a replacement admin before deleting the bootstrapped one.
func (a *bootstrapApp) create(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if strings.TrimSpace(login) == "" || strings.TrimSpace(password) == "" {
		a.page(w, r, "Error: login and password are required")
		return
	}
	if err := a.users.Create(login, password); err != nil {
		a.page(w, r, "Error: "+err.Error())
		return
	}
	a.page(w, r, "Created user "+login+".")
}

// delete removes a user; deleting the last one makes the store bootstrappable again.
func (a *bootstrapApp) delete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.users.Delete(id); err != nil {
		a.page(w, r, "Error: "+err.Error())
		return
	}
	a.page(w, r, "Deleted user "+id+".")
}

// status is the first-run check an SPA would call to decide whether to show
// its setup wizard: {"needsSetup": true} while the store has no users.
func (a *bootstrapApp) status(w http.ResponseWriter, _ *http.Request) {
	empty, err := a.users.IsEmpty()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"needsSetup": empty})
}
