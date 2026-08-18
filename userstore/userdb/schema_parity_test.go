package userdb_test

import (
	"sort"
	"strings"
	"testing"

	patdb "github.com/go-bumbu/userauth/service/pat/store/db"
	recoverydb "github.com/go-bumbu/userauth/service/recoverycodes/store/db"
	totpdb "github.com/go-bumbu/userauth/service/totp/store/db"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestSatelliteSchemaParity guards the temporary duplication of the satellite
// models: userdb still migrates them and the new per-service GORM stores
// migrate the same tables. If the two models drift, migrating the new one over
// userdb's table adds or alters a column and the column set changes.
//
// Delete this test together with the duplication, when userdb stops owning
// these tables.
func TestSatelliteSchemaParity(t *testing.T) {
	tests := []struct {
		table   string
		migrate func(*gorm.DB) error
	}{
		{"user_totp", func(db *gorm.DB) error { _, err := totpdb.New(db); return err }},
		{"user_recovery_codes", func(db *gorm.DB) error { _, err := recoverydb.New(db); return err }},
		{"user_pats", func(db *gorm.DB) error { _, err := patdb.New(db); return err }},
	}

	for _, tc := range tests {
		t.Run(tc.table, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			if _, err := userdb.New(db, userdb.Opts{BcryptDifficulty: bcrypt.MinCost}); err != nil {
				t.Fatalf("userdb.New: %v", err)
			}

			before := columns(t, db, tc.table)
			if len(before) == 0 {
				t.Fatalf("userdb.New did not create %s", tc.table)
			}
			if err := tc.migrate(db); err != nil {
				t.Fatalf("migrate %s with the service store: %v", tc.table, err)
			}
			after := columns(t, db, tc.table)

			if strings.Join(before, ", ") != strings.Join(after, ", ") {
				t.Errorf("schema drift on %s\nuserdb:  %s\nservice: %s",
					tc.table, strings.Join(before, ", "), strings.Join(after, ", "))
			}
		})
	}
}

// columns returns "name type" for every column of the table, sorted, so two
// schemas can be compared as strings.
func columns(t *testing.T, db *gorm.DB, table string) []string {
	t.Helper()
	if !db.Migrator().HasTable(table) {
		return nil
	}
	cts, err := db.Migrator().ColumnTypes(table)
	if err != nil {
		t.Fatalf("column types for %s: %v", table, err)
	}
	out := make([]string, 0, len(cts))
	for _, c := range cts {
		out = append(out, c.Name()+" "+c.DatabaseTypeName())
	}
	sort.Strings(out)
	return out
}
