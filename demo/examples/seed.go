package examples

import (
	"crypto/rand"
	"fmt"

	"github.com/go-bumbu/userauth/userstore/dbuser"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var seedAccounts = []struct{ id, pw string }{
	{"admin", "admin"},
	{"demo", "demo"},
	{"admin@example.com", "admin"},
	{"demo@example.com", "demo"},
}

// SeededStore opens an in-memory SQLite DB, builds a dbuser.Store, seeds the
// demo accounts, and returns the store. Shared by the demo binary and tests.
func SeededStore() (*dbuser.Store, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open in-memory sqlite: %w", err)
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		return nil, fmt.Errorf("generate TOTP encryption key: %w", err)
	}
	mgr, err := dbuser.New(db, dbuser.Opts{
		BcryptDifficulty:  4,
		DefaultEnabled:    true,
		TOTPEncryptionKey: totpKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create db store: %w", err)
	}
	for _, a := range seedAccounts {
		if err := mgr.Create(a.id, a.pw); err != nil {
			return nil, fmt.Errorf("seed user %s: %w", a.id, err)
		}
	}
	return mgr, nil
}
