package memory_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/loginflow"
	"github.com/go-bumbu/userauth/loginflow/memory"
	"github.com/google/go-cmp/cmp"
)

func TestStore(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	t.Run("set and get", func(t *testing.T) {
		store := memory.New()
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
		if diff := cmp.Diff(a, got); diff != "" {
			t.Errorf("attempt mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := memory.New()
		if _, err := store.Get(r, "nobody"); !errors.Is(err, memory.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound, got %v", err)
		}
	})

	t.Run("expired attempt is dropped", func(t *testing.T) {
		store := memory.New()
		a := loginflow.Attempt{UserID: "alice", ExpiresAt: time.Now().Add(-time.Second)}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrAttemptExpired) {
			t.Fatalf("want ErrAttemptExpired, got %v", err)
		}
		// a second Get finds nothing: the expired entry was deleted
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound after expiry cleanup, got %v", err)
		}
	})

	t.Run("clear", func(t *testing.T) {
		store := memory.New()
		a := loginflow.Attempt{UserID: "alice", ExpiresAt: time.Now().Add(time.Minute)}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}
		if err := store.Clear(r, w, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(r, "alice"); !errors.Is(err, memory.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound after clear, got %v", err)
		}
	})
}
