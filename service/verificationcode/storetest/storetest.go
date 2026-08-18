// Package storetest provides a conformance suite that every
// verificationcode.CodeStore implementation must pass. Store tests call Run
// with a factory that returns a fresh, empty store.
package storetest

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/verificationcode"
)

// Run exercises the CodeStore contract against a fresh store per subtest.
//
//nolint:gocyclo // Conformance suite with multiple test scenarios is inherently complex
func Run(t *testing.T, newStore func(t *testing.T) verificationcode.CodeStore) {
	t.Helper()

	future := time.Now().UTC().Add(10 * time.Minute)
	past := time.Now().UTC().Add(-time.Minute)

	t.Run("consume on empty store reports no match", func(t *testing.T) {
		s := newStore(t)
		ok, err := s.ConsumeCode("nobody", "hash", 5)
		if err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		if ok {
			t.Error("ConsumeCode on empty store = true, want false")
		}
	})

	t.Run("store then consume the matching hash succeeds", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "hash1", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		ok, err := s.ConsumeCode("u1", "hash1", 5)
		if err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		if !ok {
			t.Error("ConsumeCode with the matching hash = false, want true")
		}
	})

	t.Run("a consumed code cannot be consumed twice", func(t *testing.T) {
		// one-time use is the whole point: a replayed code is a free login
		s := newStore(t)
		if err := s.StoreCode("u1", "hash1", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		if _, err := s.ConsumeCode("u1", "hash1", 5); err != nil {
			t.Fatalf("first ConsumeCode: %v", err)
		}
		ok, err := s.ConsumeCode("u1", "hash1", 5)
		if err != nil {
			t.Fatalf("second ConsumeCode: %v", err)
		}
		if ok {
			t.Error("second ConsumeCode = true, want false")
		}
	})

	t.Run("a wrong hash does not consume the code", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "right", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		if ok, err := s.ConsumeCode("u1", "wrong", 5); err != nil || ok {
			t.Fatalf("wrong hash = (%v, %v), want (false, nil)", ok, err)
		}
		ok, err := s.ConsumeCode("u1", "right", 5)
		if err != nil {
			t.Fatalf("ConsumeCode after a wrong guess: %v", err)
		}
		if !ok {
			t.Error("a wrong guess destroyed a code that still had attempts left")
		}
	})

	t.Run("an expired code reports no match and is discarded", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "hash1", past); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		if ok, err := s.ConsumeCode("u1", "hash1", 5); err != nil || ok {
			t.Fatalf("expired code = (%v, %v), want (false, nil)", ok, err)
		}
		// discarded, not merely rejected: it must not come back to life
		if ok, err := s.ConsumeCode("u1", "hash1", 5); err != nil || ok {
			t.Fatalf("expired code after retry = (%v, %v), want (false, nil)", ok, err)
		}
	})

	t.Run("reaching maxAttempts invalidates the code", func(t *testing.T) {
		// codes are short, so the attempt cap is what makes them
		// non-brute-forceable
		s := newStore(t)
		if err := s.StoreCode("u1", "right", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		for i := 0; i < 2; i++ {
			if ok, err := s.ConsumeCode("u1", "wrong", 2); err != nil || ok {
				t.Fatalf("wrong guess %d = (%v, %v), want (false, nil)", i+1, ok, err)
			}
		}
		ok, err := s.ConsumeCode("u1", "right", 2)
		if err != nil {
			t.Fatalf("ConsumeCode after the cap: %v", err)
		}
		if ok {
			t.Error("the correct code still worked after maxAttempts wrong guesses")
		}
	})

	t.Run("storing a new code resets the attempt count", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "first", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		if ok, err := s.ConsumeCode("u1", "wrong", 2); err != nil || ok {
			t.Fatalf("wrong guess = (%v, %v), want (false, nil)", ok, err)
		}
		if err := s.StoreCode("u1", "second", future); err != nil {
			t.Fatalf("StoreCode again: %v", err)
		}
		// one wrong guess against the new code must not exhaust a budget of 2
		if ok, err := s.ConsumeCode("u1", "wrong", 2); err != nil || ok {
			t.Fatalf("wrong guess on the new code = (%v, %v), want (false, nil)", ok, err)
		}
		ok, err := s.ConsumeCode("u1", "second", 2)
		if err != nil {
			t.Fatalf("ConsumeCode: %v", err)
		}
		if !ok {
			t.Error("attempts carried over from the replaced code")
		}
	})

	t.Run("storing a new code invalidates the previous one", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "first", future); err != nil {
			t.Fatalf("StoreCode: %v", err)
		}
		if err := s.StoreCode("u1", "second", future); err != nil {
			t.Fatalf("StoreCode again: %v", err)
		}
		if ok, err := s.ConsumeCode("u1", "first", 5); err != nil || ok {
			t.Fatalf("replaced code = (%v, %v), want (false, nil)", ok, err)
		}
	})

	t.Run("codes are per user", func(t *testing.T) {
		s := newStore(t)
		if err := s.StoreCode("u1", "h1", future); err != nil {
			t.Fatalf("StoreCode u1: %v", err)
		}
		if err := s.StoreCode("u2", "h2", future); err != nil {
			t.Fatalf("StoreCode u2: %v", err)
		}
		if ok, err := s.ConsumeCode("u1", "h2", 5); err != nil || ok {
			t.Fatalf("u1 consuming u2's hash = (%v, %v), want (false, nil)", ok, err)
		}
		if ok, err := s.ConsumeCode("u2", "h2", 5); err != nil || !ok {
			t.Fatalf("u2 consuming its own hash = (%v, %v), want (true, nil)", ok, err)
		}
	})
}
