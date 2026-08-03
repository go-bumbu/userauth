package cookie_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/login"
	"github.com/go-bumbu/userauth/flow/login/attemptstore/cookie"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/securecookie"
)

func newTestStore(t *testing.T) *cookie.Store {
	t.Helper()
	store, err := cookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// applyCookies copies Set-Cookie headers from the recorder to a new request.
func applyCookies(w *httptest.ResponseRecorder, r *http.Request) *http.Request {
	resp := w.Result()
	for _, c := range resp.Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestStore(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		store := newTestStore(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		a := login.Attempt{
			UserID:              "alice",
			Satisfied:           []string{"password"},
			SessionKeepLoggedIn: true,
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}
		if err := store.Set(r, w, a); err != nil {
			t.Fatal(err)
		}

		r2 := applyCookies(w, httptest.NewRequest(http.MethodPost, "/", nil))
		got, err := store.Get(r2, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(a, got); diff != "" {
			t.Errorf("attempt mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := newTestStore(t)
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if _, err := store.Get(r, "nobody"); !errors.Is(err, cookie.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound, got %v", err)
		}
	})

	t.Run("userID mismatch", func(t *testing.T) {
		store := newTestStore(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		_ = store.Set(r, w, login.Attempt{
			UserID:    "alice",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})

		r2 := applyCookies(w, httptest.NewRequest(http.MethodPost, "/", nil))
		if _, err := store.Get(r2, "bob"); !errors.Is(err, cookie.ErrUserIDMismatch) {
			t.Fatalf("want ErrUserIDMismatch, got %v", err)
		}
	})

	t.Run("expired attempt", func(t *testing.T) {
		store := newTestStore(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		_ = store.Set(r, w, login.Attempt{
			UserID:    "alice",
			ExpiresAt: time.Now().Add(-time.Second),
		})

		r2 := applyCookies(w, httptest.NewRequest(http.MethodPost, "/", nil))
		if _, err := store.Get(r2, "alice"); !errors.Is(err, cookie.ErrAttemptExpired) {
			t.Fatalf("want ErrAttemptExpired, got %v", err)
		}
	})

	t.Run("clear", func(t *testing.T) {
		store := newTestStore(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		_ = store.Set(r, w, login.Attempt{
			UserID:    "carol",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})

		// Clear writes a deletion cookie.
		w2 := httptest.NewRecorder()
		_ = store.Clear(r, w2, "carol")

		// A request with the deletion cookie should not find the attempt.
		r2 := applyCookies(w2, httptest.NewRequest(http.MethodPost, "/", nil))
		if _, err := store.Get(r2, "carol"); !errors.Is(err, cookie.ErrAttemptNotFound) {
			t.Fatalf("want ErrAttemptNotFound after clear, got %v", err)
		}
	})

	t.Run("invalid keys", func(t *testing.T) {
		if _, err := cookie.New([]byte("short"), []byte("short")); err == nil {
			t.Error("expected error for invalid key lengths")
		}
	})
}
