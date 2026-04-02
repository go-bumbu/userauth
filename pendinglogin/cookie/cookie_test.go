package cookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/handlers/login"
	pendingcookie "github.com/go-bumbu/userauth/pendinglogin/cookie"
	"github.com/gorilla/securecookie"
)

func newTestStore(t *testing.T) *pendingcookie.Store {
	t.Helper()
	store, err := pendingcookie.New(
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

func TestStore_SetAndGet(t *testing.T) {
	store := newTestStore(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	data := login.PendingLogin{
		UserID:         "alice",
		KeepMeLoggedIn: true,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	if err := store.SetPendingLogin(r, w, data); err != nil {
		t.Fatal(err)
	}

	// Build a new request with the cookie from the response.
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2 = applyCookies(w, r2)

	got, err := store.GetPendingLogin(r2, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "alice" {
		t.Errorf("expected userID alice, got %s", got.UserID)
	}
	if !got.KeepMeLoggedIn {
		t.Error("expected KeepMeLoggedIn true")
	}
}

func TestStore_GetNotFound(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := store.GetPendingLogin(r, "nobody")
	if err == nil {
		t.Error("expected error for missing pending login cookie")
	}
}

func TestStore_UserIDMismatch(t *testing.T) {
	store := newTestStore(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_ = store.SetPendingLogin(r, w, login.PendingLogin{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2 = applyCookies(w, r2)

	_, err := store.GetPendingLogin(r2, "bob")
	if err == nil {
		t.Error("expected error for userID mismatch")
	}
}

func TestStore_Clear(t *testing.T) {
	store := newTestStore(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_ = store.SetPendingLogin(r, w, login.PendingLogin{
		UserID:    "carol",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	// Clear writes a deletion cookie.
	w2 := httptest.NewRecorder()
	_ = store.ClearPendingLogin(r, w2, "carol")

	// A request with the deletion cookie should not find the pending login.
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2 = applyCookies(w2, r2)

	_, err := store.GetPendingLogin(r2, "carol")
	if err == nil {
		t.Error("expected error after clearing pending login cookie")
	}
}

func TestStore_InvalidKeys(t *testing.T) {
	_, err := pendingcookie.New([]byte("short"), []byte("short"))
	if err == nil {
		t.Error("expected error for invalid key lengths")
	}
}
