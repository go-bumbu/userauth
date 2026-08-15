package login_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/login"
	throttlememory "github.com/go-bumbu/userauth/flow/login/throttlestore/memory"
)

func TestThrottle_FreeFailuresAllowed(t *testing.T) {
	th := &login.Throttle{Store: throttlememory.New()}

	for i := 0; i < login.DefaultFreeFailures; i++ {
		ok, err := th.Allow("u", "totp")
		if err != nil || !ok {
			t.Fatalf("attempt %d should be allowed: ok=%v err=%v", i+1, ok, err)
		}
		if err := th.Fail("u", "totp"); err != nil {
			t.Fatalf("Fail: %v", err)
		}
	}
	if ok, _ := th.Allow("u", "totp"); ok {
		t.Fatal("attempt after free failures should be delayed")
	}
}

func TestThrottle_SuccessResets(t *testing.T) {
	th := &login.Throttle{Store: throttlememory.New()}

	for i := 0; i < login.DefaultFreeFailures; i++ {
		_ = th.Fail("u", "totp")
	}
	if ok, _ := th.Allow("u", "totp"); ok {
		t.Fatal("should be delayed before reset")
	}
	if err := th.Success("u", "totp"); err != nil {
		t.Fatalf("Success: %v", err)
	}
	if ok, _ := th.Allow("u", "totp"); !ok {
		t.Fatal("should be allowed after success reset")
	}
}

func TestThrottle_DelayElapses(t *testing.T) {
	th := &login.Throttle{Store: throttlememory.New(), BaseDelay: 10 * time.Millisecond}

	for i := 0; i < login.DefaultFreeFailures; i++ {
		_ = th.Fail("u", "totp")
	}
	if ok, _ := th.Allow("u", "totp"); ok {
		t.Fatal("should be delayed right after the failures")
	}
	time.Sleep(15 * time.Millisecond)
	if ok, _ := th.Allow("u", "totp"); !ok {
		t.Fatal("should be allowed after the delay elapsed")
	}
}

func TestThrottle_PerMethodIsolation(t *testing.T) {
	th := &login.Throttle{Store: throttlememory.New()}

	for i := 0; i < login.DefaultFreeFailures; i++ {
		_ = th.Fail("u", "totp")
	}
	if ok, _ := th.Allow("u", "recovery"); !ok {
		t.Fatal("failures on totp must not delay recovery")
	}
	if ok, _ := th.Allow("other", "totp"); !ok {
		t.Fatal("failures for one user must not delay another")
	}
}

func TestThrottle_NoStoreFailsClosed(t *testing.T) {
	th := &login.Throttle{}
	if ok, err := th.Allow("u", "totp"); ok || err == nil {
		t.Fatal("throttle without store must fail closed with an error")
	}
}

func TestResendLimiter_FirstFreeThenWait(t *testing.T) {
	l := &login.ResendLimiter{Store: throttlememory.New()}

	if ok, err := l.Allow("u", "email"); err != nil || !ok {
		t.Fatalf("first issuance should be allowed: ok=%v err=%v", ok, err)
	}
	_ = l.Record("u", "email")
	if ok, _ := l.Allow("u", "email"); ok {
		t.Fatal("second issuance within the interval should be denied")
	}
}

func TestResendLimiter_WaitElapses(t *testing.T) {
	l := &login.ResendLimiter{Store: throttlememory.New(), Interval: 10 * time.Millisecond}

	_ = l.Record("u", "email")
	if ok, _ := l.Allow("u", "email"); ok {
		t.Fatal("should be denied right after issuance")
	}
	time.Sleep(15 * time.Millisecond)
	if ok, _ := l.Allow("u", "email"); !ok {
		t.Fatal("should be allowed after the interval elapsed")
	}
}

func TestResendLimiter_WaitDoubles(t *testing.T) {
	l := &login.ResendLimiter{Store: throttlememory.New(), Interval: 10 * time.Millisecond}

	_ = l.Record("u", "email")
	_ = l.Record("u", "email")
	// after two issuances the wait is 2×Interval: one interval is not enough
	time.Sleep(15 * time.Millisecond)
	if ok, _ := l.Allow("u", "email"); ok {
		t.Fatal("wait should have doubled after the second issuance")
	}
	time.Sleep(10 * time.Millisecond)
	if ok, _ := l.Allow("u", "email"); !ok {
		t.Fatal("should be allowed after the doubled wait elapsed")
	}
}

func TestResendLimiter_ResetAfterForgets(t *testing.T) {
	l := &login.ResendLimiter{
		Store:      throttlememory.New(),
		Interval:   time.Hour, // far longer than the reset: only the reset can allow
		ResetAfter: 10 * time.Millisecond,
	}

	_ = l.Record("u", "email")
	if ok, _ := l.Allow("u", "email"); ok {
		t.Fatal("should be denied within the interval")
	}
	time.Sleep(15 * time.Millisecond)
	if ok, _ := l.Allow("u", "email"); !ok {
		t.Fatal("state should be forgotten after ResetAfter")
	}
}

func TestResendLimiter_PerUserAndMethod(t *testing.T) {
	l := &login.ResendLimiter{Store: throttlememory.New()}
	_ = l.Record("u", "email")

	if ok, _ := l.Allow("u", "sms"); !ok {
		t.Fatal("email issuance must not limit sms")
	}
	if ok, _ := l.Allow("other", "email"); !ok {
		t.Fatal("issuance for one user must not limit another")
	}
}

func TestResendLimiter_SharesStoreWithThrottle(t *testing.T) {
	// One store instance may back both: the limiter namespaces its entries.
	store := throttlememory.New()
	th := &login.Throttle{Store: store}
	l := &login.ResendLimiter{Store: store}

	_ = l.Record("u", "email")
	if ok, _ := th.Allow("u", "email"); !ok {
		t.Fatal("issuance records must not count as verification failures")
	}
}

func TestResendLimiter_NoStoreFailsClosed(t *testing.T) {
	l := &login.ResendLimiter{}
	if ok, err := l.Allow("u", "email"); ok || err == nil {
		t.Fatal("limiter without store must fail closed with an error")
	}
}
