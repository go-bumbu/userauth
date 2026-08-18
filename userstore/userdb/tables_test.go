package userdb_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/userstore/userdb"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestNewCreatesOnlyItsOwnTables is the point of the modular stores: a caller
// who wants password login gets three tables, not nine. A new table appearing
// here means a concern crept back into the user store.
func TestNewCreatesOnlyItsOwnTables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := userdb.New(db, userdb.Opts{BcryptDifficulty: bcrypt.MinCost}); err != nil {
		t.Fatalf("userdb.New: %v", err)
	}

	var got []string
	if err := db.Raw(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&got).Error; err != nil {
		t.Fatalf("list tables: %v", err)
	}
	sort.Strings(got)

	want := []string{"user_groups", "user_models", "user_pending_email_changes"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("tables created = [%s], want [%s]", strings.Join(got, ", "), strings.Join(want, ", "))
	}
}
