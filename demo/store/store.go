package store

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/go-bumbu/userauth/userstore/dbusers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var seedAccounts = []struct{ id, pw string }{
	{"admin", "admin"},
	{"demo", "demo"},
	{"admin@example.com", "admin"},
	{"demo@example.com", "demo"},
}

// New opens an in-memory SQLite DB, builds a dbusers.DbManager, seeds the demo
// accounts, and returns the manager plus a Registry pre-populated with seeded IDs.
func New() (*dbusers.DbManager, *Registry, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("open in-memory sqlite: %w", err)
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		return nil, nil, fmt.Errorf("generate TOTP encryption key: %w", err)
	}
	mgr, err := dbusers.NewDbManager(db, dbusers.ManagerOpts{
		BcryptDifficulty:  4,
		DefaultEnabled:    true,
		TOTPEncryptionKey: totpKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create db manager: %w", err)
	}
	reg := &Registry{}
	for _, a := range seedAccounts {
		if err := mgr.Create(a.id, a.pw); err != nil {
			return nil, nil, fmt.Errorf("seed user %s: %w", a.id, err)
		}
		reg.Add(a.id)
	}
	return mgr, reg, nil
}

// Registry is a tiny thread-safe set of known user IDs. The demo needs it because
// dbusers.DbManager has no "list all users" API: register adds IDs, usersadmin lists them.
type Registry struct {
	mu  sync.Mutex
	ids []string
}

func (r *Registry) Add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
}

func (r *Registry) List() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.ids))
	copy(out, r.ids)
	return out
}
