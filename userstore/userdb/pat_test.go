package userdb_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/storetest"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newPatTestStore(t *testing.T) *userdb.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := userdb.New(db, userdb.Opts{BcryptDifficulty: 4, DefaultEnabled: true})
	if err != nil {
		t.Fatalf("userdb.New: %v", err)
	}
	return s
}

func TestPatStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) pat.TokenStore {
		return newPatTestStore(t).PATStore()
	})
}

func TestPatCascadeOnUserDelete(t *testing.T) {
	s := newPatTestStore(t)
	if err := s.Create("alice@example.com", "secret"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	user, err := s.GetUserByLogin("alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByLogin: %v", err)
	}
	rec := pat.TokenRecord{
		TokenID:    "cascade1",
		UserID:     user.ID,
		Name:       "will be cascaded",
		SecretHash: "deadbeef",
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.PATStore().Insert(rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := s.Delete(user.ID); err != nil {
		t.Fatalf("user Delete: %v", err)
	}
	if _, err := s.PATStore().GetByTokenID("cascade1"); !errors.Is(err, pat.ErrTokenNotFound) {
		t.Errorf("pat row should be cascaded on user delete, got %v", err)
	}
}
