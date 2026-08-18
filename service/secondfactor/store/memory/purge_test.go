package memory

import (
	"testing"

	"github.com/go-bumbu/userauth"
)

func TestPurgeUser(t *testing.T) {
	s := New()
	if err := s.SetEnabled("u1", userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("SetEnabled u1 email: %v", err)
	}
	if err := s.SetEnabled("u1", userauth.SecondFactorSMS, true); err != nil {
		t.Fatalf("SetEnabled u1 sms: %v", err)
	}
	if err := s.SetEnabled("u2", userauth.SecondFactorTOTP, true); err != nil {
		t.Fatalf("SetEnabled u2 totp: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if on, _ := s.Enabled("u1", userauth.SecondFactorEmail); on {
		t.Error("u1's email flag still set after purge")
	}
	if on, _ := s.Enabled("u1", userauth.SecondFactorSMS); on {
		t.Error("u1's sms flag still set after purge")
	}
	if on, _ := s.Enabled("u2", userauth.SecondFactorTOTP); !on {
		t.Error("u2's totp flag was affected by u1's purge")
	}
}
