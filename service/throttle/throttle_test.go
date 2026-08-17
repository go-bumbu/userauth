package throttle_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/throttle"
	"github.com/go-bumbu/userauth/service/throttle/store/memory"
)

func TestBackoff_FreeFailuresAllowed(t *testing.T) {
	b := &throttle.Backoff{Store: memory.New()}

	for i := 0; i < throttle.DefaultFreeFailures; i++ {
		ok, err := b.Allow("u", "totp")
		if err != nil || !ok {
			t.Fatalf("attempt %d should be allowed: ok=%v err=%v", i+1, ok, err)
		}
		if err := b.Fail("u", "totp"); err != nil {
			t.Fatalf("Fail: %v", err)
		}
	}
	if ok, _ := b.Allow("u", "totp"); ok {
		t.Fatal("attempt after free failures should be delayed")
	}
}

func TestBackoff_SuccessResets(t *testing.T) {
	b := &throttle.Backoff{Store: memory.New()}

	for i := 0; i < throttle.DefaultFreeFailures; i++ {
		_ = b.Fail("u", "totp")
	}
	if ok, _ := b.Allow("u", "totp"); ok {
		t.Fatal("should be delayed before reset")
	}
	if err := b.Success("u", "totp"); err != nil {
		t.Fatalf("Success: %v", err)
	}
	if ok, _ := b.Allow("u", "totp"); !ok {
		t.Fatal("should be allowed after success reset")
	}
}

func TestBackoff_DelayElapses(t *testing.T) {
	b := &throttle.Backoff{Store: memory.New(), BaseDelay: 10 * time.Millisecond}

	for i := 0; i < throttle.DefaultFreeFailures; i++ {
		_ = b.Fail("u", "totp")
	}
	if ok, _ := b.Allow("u", "totp"); ok {
		t.Fatal("should be delayed right after the failures")
	}
	time.Sleep(15 * time.Millisecond)
	if ok, _ := b.Allow("u", "totp"); !ok {
		t.Fatal("should be allowed after the delay elapsed")
	}
}

func TestBackoff_DelayCappedAtMax(t *testing.T) {
	b := &throttle.Backoff{
		Store:        memory.New(),
		FreeFailures: 1,
		BaseDelay:    5 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	// Many failures: without the cap the doubling would reach seconds.
	for i := 0; i < 12; i++ {
		_ = b.Fail("u", "totp")
	}
	if ok, _ := b.Allow("u", "totp"); ok {
		t.Fatal("should be delayed right after the failures")
	}
	time.Sleep(15 * time.Millisecond)
	if ok, _ := b.Allow("u", "totp"); !ok {
		t.Fatal("delay must be capped at MaxDelay")
	}
}

func TestBackoff_PerKeyAndMethodIsolation(t *testing.T) {
	b := &throttle.Backoff{Store: memory.New()}

	for i := 0; i < throttle.DefaultFreeFailures; i++ {
		_ = b.Fail("u", "totp")
	}
	if ok, _ := b.Allow("u", "recovery"); !ok {
		t.Fatal("failures on totp must not delay recovery")
	}
	if ok, _ := b.Allow("other", "totp"); !ok {
		t.Fatal("failures for one key must not delay another")
	}
}

func TestBackoff_NoStoreFailsClosed(t *testing.T) {
	b := &throttle.Backoff{}
	if ok, err := b.Allow("u", "totp"); ok || err == nil {
		t.Fatal("Allow without store must fail closed with an error")
	}
	if err := b.Fail("u", "totp"); err == nil {
		t.Fatal("Fail without store must error")
	}
	if err := b.Success("u", "totp"); err == nil {
		t.Fatal("Success without store must error")
	}
}
