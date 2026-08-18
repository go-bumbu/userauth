package db

import (
	"errors"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/storetest"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := New(gdb)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) pat.TokenStore {
		return newStore(t)
	})
}

// TestScopesRoundTrip pins the JSON encoding of Scopes: the column is opaque
// text, so a decoding slip would silently widen or drop a token's permissions.
func TestScopesRoundTrip(t *testing.T) {
	s := newStore(t)
	in := pat.TokenRecord{
		TokenID:    "t1",
		UserID:     "u1",
		Name:       "scoped",
		SecretHash: "hash",
		Scopes:     []string{"read", "write"},
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.Insert(in); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.GetByTokenID("t1")
	if err != nil {
		t.Fatalf("GetByTokenID: %v", err)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "read" || got.Scopes[1] != "write" {
		t.Errorf("Scopes = %v, want [read write]", got.Scopes)
	}

	// no scopes must round-trip as nil, not as a one-element slice of ""
	if err := s.Insert(pat.TokenRecord{TokenID: "t2", UserID: "u1", Name: "plain", SecretHash: "h"}); err != nil {
		t.Fatalf("Insert unscoped: %v", err)
	}
	got2, err := s.GetByTokenID("t2")
	if err != nil {
		t.Fatalf("GetByTokenID unscoped: %v", err)
	}
	if len(got2.Scopes) != 0 {
		t.Errorf("unscoped Scopes = %v, want empty", got2.Scopes)
	}
}

func TestPurgeUser(t *testing.T) {
	s := newStore(t)
	if err := s.Insert(pat.TokenRecord{TokenID: "t1", UserID: "u1", Name: "a", SecretHash: "h1"}); err != nil {
		t.Fatalf("Insert t1: %v", err)
	}
	if err := s.Insert(pat.TokenRecord{TokenID: "t2", UserID: "u2", Name: "b", SecretHash: "h2"}); err != nil {
		t.Fatalf("Insert t2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if _, err := s.GetByTokenID("t1"); !errors.Is(err, pat.ErrTokenNotFound) {
		t.Errorf("t1 after purge: err = %v, want pat.ErrTokenNotFound", err)
	}
	if _, err := s.GetByTokenID("t2"); err != nil {
		t.Errorf("t2 removed by purging u1: %v", err)
	}
}
