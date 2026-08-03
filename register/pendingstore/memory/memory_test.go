package memory_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/register"
	"github.com/go-bumbu/userauth/register/pendingstore/memory"
	"github.com/google/go-cmp/cmp"
)

func TestStore(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	t.Run("set and get", func(t *testing.T) {
		store := memory.New()
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
		if diff := cmp.Diff(reg, got); diff != "" {
			t.Errorf("registration mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := memory.New()
		if _, err := store.Get(r, "nobody"); !errors.Is(err, memory.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound, got %v", err)
		}
	})

	t.Run("expired registration is dropped", func(t *testing.T) {
		store := memory.New()
		reg := register.Registration{LoginID: "alice", ExpiresAt: time.Now().Add(-time.Second)}
		if err := store.Set(r, w, reg); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrRegistrationExpired) {
			t.Fatalf("want ErrRegistrationExpired, got %v", err)
		}
		// a second Get finds nothing: the expired entry was deleted
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound after expiry cleanup, got %v", err)
		}
	})

	t.Run("overwrite", func(t *testing.T) {
		store := memory.New()
		if err := store.Set(r, w, register.Registration{LoginID: "alice", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(r, w, register.Registration{LoginID: "alice", Satisfied: []string{"email"}, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(r, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"email"}, got.Satisfied); diff != "" {
			t.Errorf("satisfied mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("clear", func(t *testing.T) {
		store := memory.New()
		if err := store.Set(r, w, register.Registration{LoginID: "alice", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := store.Clear(r, w, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrRegistrationNotFound) {
			t.Fatalf("want ErrRegistrationNotFound after clear, got %v", err)
		}
	})
}
