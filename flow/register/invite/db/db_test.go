package db_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/register/invite"
	invitedb "github.com/go-bumbu/userauth/flow/register/invite/db"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) *invitedb.Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// each pooled connection would get its own :memory: database; one
	// connection keeps the migrated schema visible to concurrent consumers
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	store, err := invitedb.New(gdb)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStore(t *testing.T) {
	t.Run("save and get", func(t *testing.T) {
		store := newTestStore(t)
		inv := invite.Invite{
			Code:      "abc123",
			Note:      "team A",
			Email:     "a@example.com",
			UsesLeft:  3,
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			CreatedAt: time.Now().UTC(),
		}
		if err := store.Save(inv); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get("abc123")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(inv, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
			t.Errorf("invite mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := newTestStore(t)
		if _, err := store.Get("nope"); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("want ErrInviteNotFound, got %v", err)
		}
	})

	t.Run("save overwrites", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Save(invite.Invite{Code: "abc", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(invite.Invite{Code: "abc", UsesLeft: 5, Revoked: true}); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get("abc")
		if err != nil {
			t.Fatal(err)
		}
		if got.UsesLeft != 5 || !got.Revoked {
			t.Errorf("want overwritten invite (uses 5, revoked), got %+v", got)
		}
	})

	t.Run("list", func(t *testing.T) {
		store := newTestStore(t)
		for _, code := range []string{"a", "b", "c"} {
			if err := store.Save(invite.Invite{Code: code, UsesLeft: 1}); err != nil {
				t.Fatal(err)
			}
		}
		list, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 3 {
			t.Errorf("want 3 invites, got %d", len(list))
		}
	})

	t.Run("delete", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Save(invite.Invite{Code: "abc", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete("abc"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get("abc"); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("want ErrInviteNotFound after delete, got %v", err)
		}
	})

	t.Run("consume decrements", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Save(invite.Invite{Code: "abc", UsesLeft: 2}); err != nil {
			t.Fatal(err)
		}
		ok, err := store.Consume("abc", "")
		if err != nil || !ok {
			t.Fatalf("want consume ok, got ok=%v err=%v", ok, err)
		}
		got, err := store.Get("abc")
		if err != nil {
			t.Fatal(err)
		}
		if got.UsesLeft != 1 {
			t.Errorf("want 1 use left, got %d", got.UsesLeft)
		}
	})

	t.Run("consume rejects", func(t *testing.T) {
		store := newTestStore(t)
		invites := []invite.Invite{
			{Code: "revoked", UsesLeft: 1, Revoked: true},
			{Code: "exhausted", UsesLeft: 0},
			{Code: "expired", UsesLeft: 1, ExpiresAt: time.Now().Add(-time.Minute)},
			{Code: "bound", UsesLeft: 1, Email: "a@example.com"},
		}
		for _, inv := range invites {
			if err := store.Save(inv); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range []struct{ code, email string }{
			{"unknown", ""},
			{"revoked", ""},
			{"exhausted", ""},
			{"expired", ""},
			{"bound", "b@example.com"},
		} {
			ok, err := store.Consume(tc.code, tc.email)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Errorf("want consume of %q rejected", tc.code)
			}
		}
		// email-bound invite consumable by the bound email
		ok, err := store.Consume("bound", "a@example.com")
		if err != nil || !ok {
			t.Errorf("want bound invite consumable by matching email, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("no expiry means never expires", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Save(invite.Invite{Code: "forever", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		ok, err := store.Consume("forever", "")
		if err != nil || !ok {
			t.Errorf("want zero-expiry invite consumable, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("concurrent consume of single-use invite", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Save(invite.Invite{Code: "once", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		const n = 8
		var wg sync.WaitGroup
		results := make(chan bool, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := store.Consume("once", "")
				if err != nil {
					t.Error(err)
				}
				results <- ok
			}()
		}
		wg.Wait()
		close(results)
		succeeded := 0
		for ok := range results {
			if ok {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Errorf("want exactly 1 successful consume, got %d", succeeded)
		}
	})
}
