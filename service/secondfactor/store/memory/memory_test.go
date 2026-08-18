package memory_test

import (
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/secondfactor"
	"github.com/go-bumbu/userauth/service/secondfactor/store/memory"
)

func TestFlagsRoundTrip(t *testing.T) {
	var s secondfactor.Store = memory.New()

	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || on {
		t.Fatalf("unset flag = (%v, %v), want (false, nil)", on, err)
	}
	if err := s.SetEnabled("u1", userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || !on {
		t.Fatalf("enabled flag = (%v, %v), want (true, nil)", on, err)
	}

	// factors are independent: turning email on must not turn SMS on
	if on, err := s.Enabled("u1", userauth.SecondFactorSMS); err != nil || on {
		t.Fatalf("other factor = (%v, %v), want (false, nil)", on, err)
	}
	// users are independent
	if on, err := s.Enabled("u2", userauth.SecondFactorEmail); err != nil || on {
		t.Fatalf("other user = (%v, %v), want (false, nil)", on, err)
	}

	if err := s.SetEnabled("u1", userauth.SecondFactorEmail, false); err != nil {
		t.Fatalf("SetEnabled off: %v", err)
	}
	if on, err := s.Enabled("u1", userauth.SecondFactorEmail); err != nil || on {
		t.Fatalf("disabled flag = (%v, %v), want (false, nil)", on, err)
	}
}

func TestFlagAdaptsToAvailability(t *testing.T) {
	store := memory.New()
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
