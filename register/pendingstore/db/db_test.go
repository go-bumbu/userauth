package db_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/register"
	pendingdb "github.com/go-bumbu/userauth/register/pendingstore/db"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) *pendingdb.Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := pendingdb.New(gdb)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStore(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	t.Run("set and get", func(t *testing.T) {
		store := newTestStore(t)
		reg := register.Registration{
			LoginID:    "alice",
			PassHash:   "$2a$10$hash",
			Email:      "alice@example.com",
			InviteCode: "inv123",
			Satisfied:  []string{"invite"},
			ExpiresAt:  time.Now().Add(5 * time.Minute),
		}
		if err := store.Set(r, w, reg); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(r, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(reg, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
			t.Errorf("registration mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := newTestStore(t)
		if _, err := store.Get(r, "nobody"); !errors.Is(err, pendingdb.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound, got %v", err)
		}
	})

	t.Run("expired registration is dropped", func(t *testing.T) {
		store := newTestStore(t)
		reg := register.Registration{LoginID: "bob", ExpiresAt: time.Now().Add(-time.Second)}
		if err := store.Set(r, w, reg); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "bob"); !errors.Is(err, pendingdb.ErrRegistrationExpired) {
			t.Fatalf("want ErrRegistrationExpired, got %v", err)
		}
		// a second Get finds nothing: the expired row was deleted
		if _, err := store.Get(r, "bob"); !errors.Is(err, pendingdb.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound after expiry cleanup, got %v", err)
		}
	})

	t.Run("clear", func(t *testing.T) {
		store := newTestStore(t)
		reg := register.Registration{LoginID: "carol", ExpiresAt: time.Now().Add(time.Minute)}
		if err := store.Set(r, w, reg); err != nil {
			t.Fatal(err)
		}
		if err := store.Clear(r, w, "carol"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "carol"); !errors.Is(err, pendingdb.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound after clear, got %v", err)
		}
	})

	t.Run("overwrites previous", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Set(r, w, register.Registration{
			LoginID:   "dave",
			PassHash:  "old",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(r, w, register.Registration{
			LoginID:   "dave",
			PassHash:  "new",
			Satisfied: []string{"invite", "email"},
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(r, "dave")
		if err != nil {
			t.Fatal(err)
		}
		if got.PassHash != "new" {
			t.Errorf("want overwritten hash, got %q", got.PassHash)
		}
		if diff := cmp.Diff([]string{"invite", "email"}, got.Satisfied); diff != "" {
			t.Errorf("satisfied mismatch (-want +got):\n%s", diff)
		}
	})
}
