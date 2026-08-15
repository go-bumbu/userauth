package db

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := New(gdb)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestFailures_EmptyState(t *testing.T) {
	s := newStore(t)
	count, last, err := s.Failures("u", "totp")
	if err != nil {
		t.Fatalf("Failures: %v", err)
	}
	if count != 0 || !last.IsZero() {
		t.Fatalf("want (0, zero time), got (%d, %v)", count, last)
	}
}

func TestAddFailure_CountsAndTimestamps(t *testing.T) {
	s := newStore(t)
	at := time.Now().UTC().Truncate(time.Second)

	_ = s.AddFailure("u", "totp", at.Add(-time.Minute))
	if err := s.AddFailure("u", "totp", at); err != nil {
		t.Fatalf("AddFailure: %v", err)
	}

	count, last, err := s.Failures("u", "totp")
	if err != nil {
		t.Fatalf("Failures: %v", err)
	}
	if count != 2 {
		t.Fatalf("want count 2, got %d", count)
	}
	if !last.Equal(at) {
		t.Fatalf("want last %v, got %v", at, last)
	}
}

func TestAddFailure_PerUserAndMethod(t *testing.T) {
	s := newStore(t)
	_ = s.AddFailure("u", "totp", time.Now())

	if count, _, _ := s.Failures("u", "recovery"); count != 0 {
		t.Fatal("failure on totp must not count for recovery")
	}
	if count, _, _ := s.Failures("other", "totp"); count != 0 {
		t.Fatal("failure for one user must not count for another")
	}
}

func TestClear(t *testing.T) {
	s := newStore(t)
	_ = s.AddFailure("u", "totp", time.Now())
	if err := s.Clear("u", "totp"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if count, _, _ := s.Failures("u", "totp"); count != 0 {
		t.Fatal("state should be gone after Clear")
	}
}

func TestClear_NoState(t *testing.T) {
	s := newStore(t)
	if err := s.Clear("nobody", "totp"); err != nil {
		t.Fatalf("Clear on empty state should not error: %v", err)
	}
}
