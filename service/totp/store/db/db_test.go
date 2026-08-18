package db

import (
	"testing"

	"github.com/go-bumbu/userauth/service/totp"
	"github.com/go-bumbu/userauth/service/totp/storetest"
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

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) totp.Store {
		return newStore(t)
	})
}

func TestAvailable(t *testing.T) {
	s := newStore(t)

	if ok, err := s.Available("nobody"); err != nil || ok {
		t.Fatalf("Available on empty store = (%v, %v), want (false, nil)", ok, err)
	}
	// a pending enrolment is not available: the user cannot produce codes yet
	if err := s.Set("u1", totp.Record{Secret: "s", Enabled: false}); err != nil {
		t.Fatalf("Set pending: %v", err)
	}
	if ok, err := s.Available("u1"); err != nil || ok {
		t.Fatalf("Available for pending enrolment = (%v, %v), want (false, nil)", ok, err)
	}
	if err := s.Set("u1", totp.Record{Secret: "s", Enabled: true}); err != nil {
		t.Fatalf("Set confirmed: %v", err)
	}
	if ok, err := s.Available("u1"); err != nil || !ok {
		t.Fatalf("Available for confirmed enrolment = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestPurgeUser(t *testing.T) {
	s := newStore(t)
	if err := s.Set("u1", totp.Record{Secret: "s1", Enabled: true}); err != nil {
		t.Fatalf("Set u1: %v", err)
	}
	if err := s.Set("u2", totp.Record{Secret: "s2", Enabled: true}); err != nil {
		t.Fatalf("Set u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if _, err := s.Get("u1"); err == nil {
		t.Error("u1 record survived PurgeUser")
	}
	if _, err := s.Get("u2"); err != nil {
		t.Errorf("u2 record removed by purging u1: %v", err)
	}
}
