package db_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/loginflow"
	attemptdb "github.com/go-bumbu/userauth/loginflow/attemptstore/db"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) *attemptdb.Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := attemptdb.New(gdb)
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
		a := loginflow.Attempt{
			UserID:              "alice",
			Satisfied:           []string{"password"},
			SessionKeepLoggedIn: true,
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(r, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(a, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
			t.Errorf("attempt mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := newTestStore(t)
		if _, err := store.Get(r, "nobody"); !errors.Is(err, attemptdb.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound, got %v", err)
		}
	})

	t.Run("expired attempt is dropped", func(t *testing.T) {
		store := newTestStore(t)
		a := loginflow.Attempt{UserID: "bob", ExpiresAt: time.Now().Add(-time.Second)}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "bob"); !errors.Is(err, attemptdb.ErrAttemptExpired) {
			t.Fatalf("want ErrAttemptExpired, got %v", err)
		}
		// a second Get finds nothing: the expired row was deleted
		if _, err := store.Get(r, "bob"); !errors.Is(err, attemptdb.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound after expiry cleanup, got %v", err)
		}
	})

	t.Run("clear", func(t *testing.T) {
		store := newTestStore(t)
		a := loginflow.Attempt{UserID: "carol", ExpiresAt: time.Now().Add(time.Minute)}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}
		if err := store.Clear(r, w, "carol"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "carol"); !errors.Is(err, attemptdb.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound after clear, got %v", err)
		}
	})

	t.Run("overwrites previous", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Set(r, w, loginflow.Attempt{
			UserID:    "dave",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(r, w, loginflow.Attempt{
			UserID:              "dave",
			Satisfied:           []string{"password", "totp"},
			SessionKeepLoggedIn: true,
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(r, "dave")
		if err != nil {
			t.Fatal(err)
		}
		if !got.SessionKeepLoggedIn {
			t.Error("expected overwritten SessionKeepLoggedIn true")
		}
		if diff := cmp.Diff([]string{"password", "totp"}, got.Satisfied); diff != "" {
			t.Errorf("satisfied mismatch (-want +got):\n%s", diff)
		}
	})
}
