// Package storetest provides a conformance suite that every totp.Store
// implementation must pass. Store tests call Run with a factory that returns a
// fresh, empty store.
package storetest

import (
	"errors"
	"testing"

	"github.com/go-bumbu/userauth/service/totp"
)

// Run exercises the totp.Store contract against a fresh store per subtest.
//
//nolint:gocyclo // Conformance suite with multiple test scenarios is inherently complex
func Run(t *testing.T, newStore func(t *testing.T) totp.Store) {
	t.Helper()

	t.Run("get on empty store reports ErrNotEnrolled", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Get("nobody"); !errors.Is(err, totp.ErrNotEnrolled) {
			t.Errorf("Get on empty store: err = %v, want totp.ErrNotEnrolled", err)
		}
	})

	t.Run("set and get round-trip", func(t *testing.T) {
		s := newStore(t)
		in := totp.Record{Secret: "JBSWY3DPEHPK3PXP", KeyID: "k1", Enabled: true} //nolint:gosec // well-known RFC example secret, not a credential
		if err := s.Set("user1", in); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := s.Get("user1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != in {
			t.Errorf("round-trip = %+v, want %+v", got, in)
		}
	})

	t.Run("set replaces the previous record", func(t *testing.T) {
		s := newStore(t)
		if err := s.Set("user1", totp.Record{Secret: "first", Enabled: false}); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := s.Set("user1", totp.Record{Secret: "second", Enabled: true}); err != nil {
			t.Fatalf("Set again: %v", err)
		}
		got, err := s.Get("user1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Secret != "second" || !got.Enabled {
			t.Errorf("after replace = %+v, want secret=second enabled=true", got)
		}
	})

	t.Run("records are per user", func(t *testing.T) {
		s := newStore(t)
		if err := s.Set("user1", totp.Record{Secret: "s1", Enabled: true}); err != nil {
			t.Fatalf("Set user1: %v", err)
		}
		if err := s.Set("user2", totp.Record{Secret: "s2", Enabled: false}); err != nil {
			t.Fatalf("Set user2: %v", err)
		}
		got1, err := s.Get("user1")
		if err != nil {
			t.Fatalf("Get user1: %v", err)
		}
		got2, err := s.Get("user2")
		if err != nil {
			t.Fatalf("Get user2: %v", err)
		}
		if got1.Secret != "s1" || got2.Secret != "s2" {
			t.Errorf("cross-user leak: user1=%+v user2=%+v", got1, got2)
		}
	})

	t.Run("empty key id round-trips as empty", func(t *testing.T) {
		// secrets stored in the clear (no cipher configured) and rows written
		// before the key-id column existed must not gain a key id
		s := newStore(t)
		if err := s.Set("user1", totp.Record{Secret: "plain", Enabled: true}); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := s.Get("user1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.KeyID != "" {
			t.Errorf("KeyID = %q, want empty", got.KeyID)
		}
	})

	t.Run("delete removes the record", func(t *testing.T) {
		s := newStore(t)
		if err := s.Set("user1", totp.Record{Secret: "s1", Enabled: true}); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := s.Delete("user1"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get("user1"); !errors.Is(err, totp.ErrNotEnrolled) {
			t.Errorf("Get after Delete: err = %v, want totp.ErrNotEnrolled", err)
		}
	})

	t.Run("delete of an absent record is not an error", func(t *testing.T) {
		s := newStore(t)
		if err := s.Delete("nobody"); err != nil {
			t.Errorf("Delete absent: %v", err)
		}
	})

	t.Run("delete affects only the given user", func(t *testing.T) {
		s := newStore(t)
		if err := s.Set("user1", totp.Record{Secret: "s1"}); err != nil {
			t.Fatalf("Set user1: %v", err)
		}
		if err := s.Set("user2", totp.Record{Secret: "s2"}); err != nil {
			t.Fatalf("Set user2: %v", err)
		}
		if err := s.Delete("user1"); err != nil {
			t.Fatalf("Delete user1: %v", err)
		}
		if _, err := s.Get("user2"); err != nil {
			t.Errorf("user2 gone after deleting user1: %v", err)
		}
	})
}
