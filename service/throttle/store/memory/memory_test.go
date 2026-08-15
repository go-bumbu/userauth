package memory

import (
	"testing"
	"time"
)

func TestFailures_EmptyState(t *testing.T) {
	s := New()
	count, last, err := s.Failures("u", "totp")
	if err != nil {
		t.Fatalf("Failures: %v", err)
	}
	if count != 0 || !last.IsZero() {
		t.Fatalf("want (0, zero time), got (%d, %v)", count, last)
	}
}

func TestAddFailure_CountsAndTimestamps(t *testing.T) {
	s := New()
	at := time.Now()

	_ = s.AddFailure("u", "totp", at.Add(-time.Minute))
	if err := s.AddFailure("u", "totp", at); err != nil {
		t.Fatalf("AddFailure: %v", err)
	}

	count, last, _ := s.Failures("u", "totp")
	if count != 2 {
		t.Fatalf("want count 2, got %d", count)
	}
	if !last.Equal(at) {
		t.Fatalf("want last %v, got %v", at, last)
	}
}

func TestAddFailure_PerUserAndMethod(t *testing.T) {
	s := New()
	_ = s.AddFailure("u", "totp", time.Now())

	if count, _, _ := s.Failures("u", "recovery"); count != 0 {
		t.Fatal("failure on totp must not count for recovery")
	}
	if count, _, _ := s.Failures("other", "totp"); count != 0 {
		t.Fatal("failure for one user must not count for another")
	}
}

func TestClear(t *testing.T) {
	s := New()
	_ = s.AddFailure("u", "totp", time.Now())
	if err := s.Clear("u", "totp"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if count, _, _ := s.Failures("u", "totp"); count != 0 {
		t.Fatal("state should be gone after Clear")
	}
}
