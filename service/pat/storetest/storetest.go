// Package storetest provides a conformance suite that every pat.TokenStore
// implementation must pass. Store tests call Run with a factory that returns
// a fresh, empty store.
package storetest

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
)

// Run exercises the TokenStore contract against a fresh store per subtest.
//
//nolint:gocyclo // Conformance suite with multiple test scenarios is inherently complex
func Run(t *testing.T, newStore func(t *testing.T) pat.TokenStore) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	rec := func(tokenID, userID string) pat.TokenRecord {
		return pat.TokenRecord{
			TokenID:    tokenID,
			UserID:     userID,
			Name:       "test token",
			SecretHash: "deadbeef",
			Scopes:     []string{"read", "write"},
			CreatedAt:  now,
		}
	}

	t.Run("insert and get round-trip", func(t *testing.T) {
		s := newStore(t)
		exp := now.Add(time.Hour)
		in := rec("tok1", "user1")
		in.ExpiresAt = &exp
		if err := s.Insert(in); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		got, err := s.GetByTokenID("tok1")
		if err != nil {
			t.Fatalf("GetByTokenID: %v", err)
		}
		if got.TokenID != "tok1" || got.UserID != "user1" || got.Name != "test token" ||
			got.SecretHash != "deadbeef" {
			t.Errorf("round-trip mismatch: %+v", got)
		}
		if len(got.Scopes) != 2 || got.Scopes[0] != "read" || got.Scopes[1] != "write" {
			t.Errorf("scopes mismatch: %v", got.Scopes)
		}
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
			t.Errorf("expiry mismatch: %v", got.ExpiresAt)
		}
	})

	t.Run("get absent returns ErrTokenNotFound", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetByTokenID("nope"); err != pat.ErrTokenNotFound {
			t.Errorf("want ErrTokenNotFound, got %v", err)
		}
	})

	t.Run("duplicate tokenID rejected", func(t *testing.T) {
		s := newStore(t)
		if err := s.Insert(rec("dup", "user1")); err != nil {
			t.Fatalf("first Insert: %v", err)
		}
		if err := s.Insert(rec("dup", "user2")); err == nil {
			t.Error("second Insert with same TokenID should fail")
		}
	})

	t.Run("list by user, oldest first, empty scopes ok", func(t *testing.T) {
		s := newStore(t)
		a := rec("a1", "user1")
		a.CreatedAt = now.Add(-2 * time.Hour)
		a.Scopes = nil
		b := rec("b1", "user1")
		b.CreatedAt = now.Add(-1 * time.Hour)
		c := rec("c1", "user2")
		for _, r := range []pat.TokenRecord{b, a, c} {
			if err := s.Insert(r); err != nil {
				t.Fatalf("Insert %s: %v", r.TokenID, err)
			}
		}
		got, err := s.ListByUser("user1")
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(got) != 2 || got[0].TokenID != "a1" || got[1].TokenID != "b1" {
			t.Errorf("list mismatch: %+v", got)
		}
		if len(got[0].Scopes) != 0 {
			t.Errorf("empty scopes should round-trip empty, got %v", got[0].Scopes)
		}
		none, err := s.ListByUser("stranger")
		if err != nil || len(none) != 0 {
			t.Errorf("ListByUser(stranger) = %v, %v", none, err)
		}
	})

	t.Run("delete is owner-scoped", func(t *testing.T) {
		s := newStore(t)
		if err := s.Insert(rec("del1", "user1")); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if err := s.Delete("user2", "del1"); err != pat.ErrTokenNotFound {
			t.Errorf("foreign delete: want ErrTokenNotFound, got %v", err)
		}
		if err := s.Delete("user1", "absent"); err != pat.ErrTokenNotFound {
			t.Errorf("absent delete: want ErrTokenNotFound, got %v", err)
		}
		if err := s.Delete("user1", "del1"); err != nil {
			t.Errorf("owner delete: %v", err)
		}
		if _, err := s.GetByTokenID("del1"); err != pat.ErrTokenNotFound {
			t.Errorf("token should be gone, got %v", err)
		}
	})

	t.Run("touch updates LastUsedAt", func(t *testing.T) {
		s := newStore(t)
		if err := s.Insert(rec("touch1", "user1")); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		when := now.Add(time.Minute)
		if err := s.Touch("touch1", when); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		got, err := s.GetByTokenID("touch1")
		if err != nil {
			t.Fatalf("GetByTokenID: %v", err)
		}
		if got.LastUsedAt == nil || !got.LastUsedAt.Equal(when) {
			t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, when)
		}
	})

	t.Run("touch on absent token returns ErrTokenNotFound", func(t *testing.T) {
		s := newStore(t)
		if err := s.Touch("absent", now); err != pat.ErrTokenNotFound {
			t.Errorf("want ErrTokenNotFound, got %v", err)
		}
	})

	t.Run("insert without expiry", func(t *testing.T) {
		s := newStore(t)
		in := rec("noexp", "user1")
		in.ExpiresAt = nil
		if err := s.Insert(in); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		got, err := s.GetByTokenID("noexp")
		if err != nil {
			t.Fatalf("GetByTokenID: %v", err)
		}
		if got.ExpiresAt != nil {
			t.Errorf("ExpiresAt should be nil, got %v", got.ExpiresAt)
		}
	})

	t.Run("insert and list multiple users", func(t *testing.T) {
		s := newStore(t)
		for _, userID := range []string{"user1", "user2", "user3"} {
			if err := s.Insert(rec("tok_"+userID, userID)); err != nil {
				t.Fatalf("Insert %s: %v", userID, err)
			}
		}
		for _, userID := range []string{"user1", "user2", "user3"} {
			got, err := s.ListByUser(userID)
			if err != nil {
				t.Errorf("ListByUser(%s): %v", userID, err)
			}
			if len(got) != 1 {
				t.Errorf("ListByUser(%s): want 1 token, got %d", userID, len(got))
			}
		}
	})

	t.Run("recoverable fields round-trip", func(t *testing.T) {
		s := newStore(t)
		in := rec("recov1", "user1")
		in.SecretEnc = "bm9uY2UtY2lwaGVydGV4dA=="
		in.KeyID = "k1"
		if err := s.Insert(in); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		got, err := s.GetByTokenID("recov1")
		if err != nil {
			t.Fatalf("GetByTokenID: %v", err)
		}
		if got.SecretEnc != in.SecretEnc || got.KeyID != "k1" {
			t.Errorf("recoverable fields mismatch: %+v", got)
		}
		if !got.Recoverable() {
			t.Error("Recoverable() should be true when SecretEnc is set")
		}
		// hash-only records stay non-recoverable
		if err := s.Insert(rec("plain1", "user1")); err != nil {
			t.Fatalf("Insert plain: %v", err)
		}
		plain, err := s.GetByTokenID("plain1")
		if err != nil {
			t.Fatalf("GetByTokenID plain: %v", err)
		}
		if plain.Recoverable() {
			t.Error("Recoverable() should be false when SecretEnc is empty")
		}
	})
}
