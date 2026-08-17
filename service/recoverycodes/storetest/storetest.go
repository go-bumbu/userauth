// Package storetest provides a conformance suite that every
// recoverycodes.Store implementation must pass. Store tests call Run with a
// factory that returns a fresh, empty store.
package storetest

import (
	"slices"
	"testing"

	"github.com/go-bumbu/userauth/service/recoverycodes"
)

// Run exercises the recoverycodes.Store contract against a fresh store per
// subtest. Hashes are opaque to the store, so the suite uses plain strings.
//
//nolint:gocyclo // Conformance suite with multiple test scenarios is inherently complex
func Run(t *testing.T, newStore func(t *testing.T) recoverycodes.Store) {
	t.Helper()

	t.Run("empty store reports no codes", func(t *testing.T) {
		s := newStore(t)
		got, err := s.Hashes("nobody")
		if err != nil {
			t.Fatalf("Hashes: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("Hashes = %v, want empty", got)
		}
		n, err := s.Count("nobody")
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n != 0 {
			t.Errorf("Count = %d, want 0", n)
		}
	})

	t.Run("replace and read back", func(t *testing.T) {
		s := newStore(t)
		in := []string{"h1", "h2", "h3"}
		if err := s.Replace("user1", in); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		got, err := s.Hashes("user1")
		if err != nil {
			t.Fatalf("Hashes: %v", err)
		}
		slices.Sort(got)
		if !slices.Equal(got, in) {
			t.Errorf("Hashes = %v, want %v (order is not significant)", got, in)
		}
		n, err := s.Count("user1")
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n != 3 {
			t.Errorf("Count = %d, want 3", n)
		}
	})

	t.Run("replace drops the previous set", func(t *testing.T) {
		s := newStore(t)
		if err := s.Replace("user1", []string{"old1", "old2"}); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if err := s.Replace("user1", []string{"new1"}); err != nil {
			t.Fatalf("Replace again: %v", err)
		}
		got, err := s.Hashes("user1")
		if err != nil {
			t.Fatalf("Hashes: %v", err)
		}
		if !slices.Equal(got, []string{"new1"}) {
			t.Errorf("Hashes = %v, want [new1]", got)
		}
	})

	t.Run("replace with nil clears", func(t *testing.T) {
		s := newStore(t)
		if err := s.Replace("user1", []string{"h1", "h2"}); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if err := s.Replace("user1", nil); err != nil {
			t.Fatalf("Replace nil: %v", err)
		}
		n, err := s.Count("user1")
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n != 0 {
			t.Errorf("Count after clearing = %d, want 0", n)
		}
	})

	t.Run("delete consumes exactly one code", func(t *testing.T) {
		s := newStore(t)
		if err := s.Replace("user1", []string{"h1", "h2", "h3"}); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if err := s.Delete("user1", "h2"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := s.Hashes("user1")
		if err != nil {
			t.Fatalf("Hashes: %v", err)
		}
		slices.Sort(got)
		if !slices.Equal(got, []string{"h1", "h3"}) {
			t.Errorf("Hashes after Delete = %v, want [h1 h3]", got)
		}
	})

	t.Run("delete of an absent hash is not an error", func(t *testing.T) {
		s := newStore(t)
		if err := s.Replace("user1", []string{"h1"}); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if err := s.Delete("user1", "nope"); err != nil {
			t.Errorf("Delete absent hash: %v", err)
		}
		if err := s.Delete("nobody", "h1"); err != nil {
			t.Errorf("Delete for unknown user: %v", err)
		}
		n, _ := s.Count("user1")
		if n != 1 {
			t.Errorf("Count = %d, want 1 (nothing should have been consumed)", n)
		}
	})

	t.Run("codes are per user", func(t *testing.T) {
		s := newStore(t)
		if err := s.Replace("user1", []string{"h1", "h2"}); err != nil {
			t.Fatalf("Replace user1: %v", err)
		}
		if err := s.Replace("user2", []string{"h1"}); err != nil {
			t.Fatalf("Replace user2: %v", err)
		}
		// the same hash value for two users must be independent
		if err := s.Delete("user1", "h1"); err != nil {
			t.Fatalf("Delete user1: %v", err)
		}
		n2, err := s.Count("user2")
		if err != nil {
			t.Fatalf("Count user2: %v", err)
		}
		if n2 != 1 {
			t.Errorf("user2 count = %d, want 1 — deleting user1's code hit user2", n2)
		}
		if err := s.Replace("user1", nil); err != nil {
			t.Fatalf("clear user1: %v", err)
		}
		if n2, _ := s.Count("user2"); n2 != 1 {
			t.Errorf("user2 count after clearing user1 = %d, want 1", n2)
		}
	})
}
