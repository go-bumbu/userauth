package userdb_test

import (
	"errors"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/totp"
	totpdb "github.com/go-bumbu/userauth/service/totp/store/db"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// failingPurger reports an error, so a test can prove that one broken satellite
// store neither hides its failure nor stops the others from cleaning up.
type failingPurger struct{ err error }

func (f failingPurger) PurgeUser(_ string) error { return f.err }

// countingPurger records whether it ran.
type countingPurger struct{ calls int }

func (c *countingPurger) PurgeUser(_ string) error {
	c.calls++
	return nil
}

func TestDeleteRunsPurgers(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tstore, err := totpdb.New(db)
	if err != nil {
		t.Fatalf("totpdb.New: %v", err)
	}
	users, err := userdb.New(db, userdb.Opts{
		BcryptDifficulty: bcrypt.MinCost,
		DefaultEnabled:   true,
		OnDelete:         []userdb.UserPurger{tstore},
	})
	if err != nil {
		t.Fatalf("userdb.New: %v", err)
	}
	if err := users.Create("alice@example.com", "secret"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	user, err := users.GetUserByLogin("alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByLogin: %v", err)
	}
	if err := tstore.Set(user.ID, totp.Record{Secret: "s", Enabled: true}); err != nil {
		t.Fatalf("Set totp: %v", err)
	}

	if err := users.Delete(user.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := tstore.Get(user.ID); !errors.Is(err, totp.ErrNotEnrolled) {
		t.Errorf("totp record survived user delete: err = %v, want totp.ErrNotEnrolled", err)
	}
}

// TestDeleteReportsPurgeFailuresAndRunsEveryPurger pins the cost of the
// non-transactional cascade: the user is gone, the failure is reported, and one
// broken store does not stop the others from cleaning up.
func TestDeleteReportsPurgeFailuresAndRunsEveryPurger(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	boom := errors.New("purger exploded")
	survivor := &countingPurger{}
	users, err := userdb.New(db, userdb.Opts{
		BcryptDifficulty: bcrypt.MinCost,
		DefaultEnabled:   true,
		OnDelete:         []userdb.UserPurger{failingPurger{err: boom}, survivor},
	})
	if err != nil {
		t.Fatalf("userdb.New: %v", err)
	}
	if err := users.Create("bob@example.com", "secret"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	user, err := users.GetUserByLogin("bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByLogin: %v", err)
	}

	if err := users.Delete(user.ID); !errors.Is(err, boom) {
		t.Fatalf("Delete err = %v, want it to wrap the purger error", err)
	}
	// the user row goes first and is not rolled back: a leaked satellite row is
	// keyed to a UUID that is never reused, so it can never be reached again
	if _, err := users.GetUser(user.ID); !errors.Is(err, userauth.ErrUserNotFound) {
		t.Errorf("GetUser after delete: err = %v, want userauth.ErrUserNotFound", err)
	}
	if survivor.calls != 1 {
		t.Errorf("purger after the failing one ran %d times, want 1", survivor.calls)
	}
}
