package db

import (
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/secondfactor"
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

func TestFlagsRoundTrip(t *testing.T) {
	s := newStore(t)

	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || on {
		t.Fatalf("unset flag = (%v, %v), want (false, nil)", on, err)
	}
	if err := s.SetEnabled("u1", userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || !on {
		t.Fatalf("enabled flag = (%v, %v), want (true, nil)", on, err)
	}
	if on, err := s.Enabled("u1", userauth.SecondFactorSMS); err != nil || on {
		t.Fatalf("other factor = (%v, %v), want (false, nil)", on, err)
	}
	if on, err := s.Enabled("u2", userauth.SecondFactorEmail); err != nil || on {
		t.Fatalf("other user = (%v, %v), want (false, nil)", on, err)
	}
}

func TestFlagAdaptsToAvailability(t *testing.T) {
	store := newStore(t)
	if err := store.SetEnabled("u1", userauth.SecondFactorSMS, true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	p := secondfactor.Provider{SMS: secondfactor.Flag{Store: store, Factor: userauth.SecondFactorSMS}}

	got, err := p.AvailableSecondFactors("u1")
	if err != nil {
		t.Fatalf("AvailableSecondFactors: %v", err)
	}
	if len(got) != 1 || got[0] != userauth.SecondFactorSMS {
		t.Errorf("got %v, want [sms]", got)
	}
}

// TestSetEnabledUpdatesInPlace pins that toggling twice does not accumulate
// rows: the (user, factor) pair is unique, so a second write must update.
func TestSetEnabledUpdatesInPlace(t *testing.T) {
	s := newStore(t)
	for _, v := range []bool{true, false, true} {
		if err := s.SetEnabled("u1", userauth.SecondFactorEmail, v); err != nil {
			t.Fatalf("SetEnabled(%v): %v", v, err)
		}
	}
	var count int64
	if err := s.db.Model(&flagModel{}).Where("user_id = ?", "u1").Count(&count).Error; err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1", count)
	}
	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || !on {
		t.Errorf("final flag = (%v, %v), want (true, nil)", on, err)
	}
}

func TestPurgeUser(t *testing.T) {
	s := newStore(t)
	if err := s.SetEnabled("u1", userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("SetEnabled u1: %v", err)
	}
	if err := s.SetEnabled("u2", userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("SetEnabled u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if on, _ := s.Enabled("u1", userauth.SecondFactorEmail); on {
		t.Error("u1 flag survived PurgeUser")
	}
	if on, _ := s.Enabled("u2", userauth.SecondFactorEmail); !on {
		t.Error("purging u1 removed u2's flag")
	}
}
