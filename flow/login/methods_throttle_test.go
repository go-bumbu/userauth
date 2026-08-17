package login_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/login"
	throttlememory "github.com/go-bumbu/userauth/service/throttle/store/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
)

// tightThrottle delays from the very first failure, for hours: one wrong
// guess and the next attempt is denied until the test ends.
func tightThrottle() *login.Throttle {
	return &login.Throttle{
		Store:        throttlememory.New(),
		FreeFailures: 1,
		BaseDelay:    time.Hour,
	}
}

func TestTOTPMethod_Throttled(t *testing.T) {
	users := fixtureUsers()
	m := login.TOTPMethod{TOTP: users, Throttle: tightThrottle()}

	t.Run("wrong guesses throttle even the correct code", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			ok, err := m.Verify("alice", "000000")
			if err != nil || ok {
				t.Fatalf("wrong code must fail without error: ok=%v err=%v", ok, err)
			}
		}
		ok, err := m.Verify("alice", totpCode(t))
		if err != nil || ok {
			t.Fatalf("throttled verify must be a credential failure: ok=%v err=%v", ok, err)
		}
	})

	t.Run("success resets and clears the state", func(t *testing.T) {
		m := login.TOTPMethod{TOTP: users, Throttle: &login.Throttle{
			Store:        throttlememory.New(),
			FreeFailures: 2,
			BaseDelay:    time.Hour,
		}}
		if ok, _ := m.Verify("alice", "000000"); ok {
			t.Fatal("wrong code must fail")
		}
		ok, err := m.Verify("alice", totpCode(t))
		if err != nil || !ok {
			t.Fatalf("correct code within budget must verify: ok=%v err=%v", ok, err)
		}
		// count cleared: one more wrong guess stays within the budget
		if ok, _ := m.Verify("alice", "000000"); ok {
			t.Fatal("wrong code must fail")
		}
		ok, err = m.Verify("alice", totpCode(t))
		if err != nil || !ok {
			t.Fatalf("correct code after reset must verify: ok=%v err=%v", ok, err)
		}
	})

	t.Run("nil throttle verifies directly", func(t *testing.T) {
		m := login.TOTPMethod{TOTP: users}
		ok, err := m.Verify("alice", totpCode(t))
		if err != nil || !ok {
			t.Fatalf("unthrottled verify: ok=%v err=%v", ok, err)
		}
	})

	t.Run("users without TOTP enrolled fail without counting", func(t *testing.T) {
		th := tightThrottle()
		m := login.TOTPMethod{TOTP: users, Throttle: th}
		// bob has no TOTP: the not-enrolled gate runs before the throttle
		for i := 0; i < 3; i++ {
			if ok, err := m.Verify("bob", "000000"); err != nil || ok {
				t.Fatalf("not-enrolled verify must fail without error: ok=%v err=%v", ok, err)
			}
		}
		if ok, _ := th.Allow("bob", login.MethodTOTP); !ok {
			t.Fatal("not-enrolled submissions must not consume the failure budget")
		}
	})
}

// staticRecovery accepts one fixed code, single-use semantics not modeled.
type staticRecovery struct{ code string }

func (s staticRecovery) VerifyRecoveryCode(_, code string) (bool, error) {
	return code == s.code, nil
}

func TestRecoveryMethod_Throttled(t *testing.T) {
	m := login.RecoveryMethod{Codes: staticRecovery{code: "abcd-1234"}, Throttle: tightThrottle()}

	if m.ID() != login.MethodRecovery {
		t.Fatalf("want method ID %q, got %q", login.MethodRecovery, m.ID())
	}
	for i := 0; i < 2; i++ {
		if ok, err := m.Verify("alice", "wrong"); err != nil || ok {
			t.Fatalf("wrong recovery code must fail without error: ok=%v err=%v", ok, err)
		}
	}
	ok, err := m.Verify("alice", "abcd-1234")
	if err != nil || ok {
		t.Fatalf("throttled verify must be a credential failure: ok=%v err=%v", ok, err)
	}
}

// failingThrottleStore errors on every call, to exercise fail-closed paths.
type failingThrottleStore struct{}

func (failingThrottleStore) Failures(_, _ string) (int, time.Time, error) {
	return 0, time.Time{}, errors.New("store down")
}
func (failingThrottleStore) AddFailure(_, _ string, _ time.Time) error {
	return errors.New("store down")
}
func (failingThrottleStore) Clear(_, _ string) error { return errors.New("store down") }

func TestTOTPMethod_ThrottleStoreErrorIsInternal(t *testing.T) {
	users := fixtureUsers()
	m := login.TOTPMethod{TOTP: users, Throttle: &login.Throttle{Store: failingThrottleStore{}}}

	if _, err := m.Verify("alice", totpCode(t)); err == nil {
		t.Fatal("a broken throttle store must surface as an internal error, not a silent pass")
	}
}

// fixtureUsers returns the same static user set the flow fixtures use.
func fixtureUsers() *staticusers.Users {
	return newFixture(nil).users
}
