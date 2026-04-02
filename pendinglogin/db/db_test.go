package db_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/handlers/login"
	pendingdb "github.com/go-bumbu/userauth/pendinglogin/db"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) *pendingdb.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := pendingdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStore_SetAndGet(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	data := login.PendingLogin{
		UserID:         "alice",
		KeepMeLoggedIn: true,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	if err := store.SetPendingLogin(r, w, data); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetPendingLogin(r, "alice")
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

func TestStore_GetExpired(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	data := login.PendingLogin{
		UserID:    "bob",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	_ = store.SetPendingLogin(r, w, data)

	_, err := store.GetPendingLogin(r, "bob")
	if err == nil {
		t.Error("expected error for expired pending login")
	}
}

func TestStore_GetNotFound(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := store.GetPendingLogin(r, "nobody")
	if err == nil {
		t.Error("expected error for missing pending login")
	}
}

func TestStore_Clear(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	_ = store.SetPendingLogin(r, w, login.PendingLogin{
		UserID:    "carol",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	_ = store.ClearPendingLogin(r, w, "carol")

	_, err := store.GetPendingLogin(r, "carol")
	if err == nil {
		t.Error("expected error after clearing pending login")
	}
}

func TestStore_OverwritesPrevious(t *testing.T) {
	store := newTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	_ = store.SetPendingLogin(r, w, login.PendingLogin{
		UserID:    "dave",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	_ = store.SetPendingLogin(r, w, login.PendingLogin{
		UserID:         "dave",
		KeepMeLoggedIn: true,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	})

	got, err := store.GetPendingLogin(r, "dave")
	if err != nil {
		t.Fatal(err)
	}
	if !got.KeepMeLoggedIn {
		t.Error("expected overwritten KeepMeLoggedIn true")
	}
}
