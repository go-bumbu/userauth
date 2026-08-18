package memory

import (
	"testing"

	"github.com/go-bumbu/userauth/service/totp"
)

func TestPurgeUser(t *testing.T) {
	s := New()
	rec1 := totp.Record{Secret: "sec1", KeyID: "k1", Enabled: true}
	rec2 := totp.Record{Secret: "sec2", KeyID: "k2", Enabled: true}

	if err := s.Set("u1", rec1); err != nil {
		t.Fatalf("Set u1: %v", err)
	}
	if err := s.Set("u2", rec2); err != nil {
		t.Fatalf("Set u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if _, err := s.Get("u1"); err != totp.ErrNotEnrolled {
		t.Errorf("u1 still exists after purge, want ErrNotEnrolled")
	}
	if got, err := s.Get("u2"); err != nil || got.Secret != "sec2" {
		t.Errorf("u2 was affected by u1's purge: %v, %v", got, err)
	}
}
