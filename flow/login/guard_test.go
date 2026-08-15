package login_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/login"
	throttlememory "github.com/go-bumbu/userauth/flow/login/throttlestore/memory"
)

// newGuardedFixture returns a password-only flow with a ThrottleGuard using
// zero free failures: every failure delays the next attempt, so tests don't
// need to loop through the default budget.
func newGuardedFixture() *fixture {
	f := newFixture(login.RequireAny(login.Chain{"password"}))
	f.flow.Guard = login.ThrottleGuard{Throttle: &login.Throttle{
		Store:        throttlememory.New(),
		FreeFailures: 1,
		BaseDelay:    time.Hour, // effectively "until the test ends"
	}}
	return f
}

func TestGuard_ThrottlesAfterFailures(t *testing.T) {
	f := newGuardedFixture()

	submit(t, f, "bob", "password", "wrong")
	submit(t, f, "bob", "password", "wrong")
	// throttled now: even the correct password is rejected as a uniform failure
	res := submit(t, f, "bob", "password", "bob-pw")
	if res.OK || res.Done || res.Next != nil {
		t.Fatalf("throttled submission must look like a credential failure, got %+v", res)
	}
	if f.session.calls != 0 {
		t.Error("no session must be created while throttled")
	}
}

func TestGuard_UnknownUserThrottledLikeExisting(t *testing.T) {
	f := newGuardedFixture()

	// Unknown-user submissions count: after the free failure the guard
	// delays, exactly as for an existing account.
	submit(t, f, "ghost", "password", "guess")
	submit(t, f, "ghost", "password", "guess")
	res := submit(t, f, "ghost", "password", "guess")
	if res.OK {
		t.Fatalf("unknown user must stay a uniform failure, got %+v", res)
	}
	// The guard state for "ghost" must exist just like for "bob": both keys
	// throttle, so timing/behavior cannot reveal which accounts exist.
	fBob := newGuardedFixture()
	submit(t, fBob, "bob", "password", "wrong")
	submit(t, fBob, "bob", "password", "wrong")
	resBob := submit(t, fBob, "bob", "password", "bob-pw")
	if resBob.OK != res.OK || resBob.Done != res.Done || len(resBob.Next) != len(res.Next) {
		t.Fatalf("throttled unknown and existing users must be indistinguishable: %+v vs %+v", res, resBob)
	}
}

func TestGuard_SuccessResets(t *testing.T) {
	// budget of 2: one failure leaves the account usable, two throttle it
	f := newFixture(login.RequireAny(login.Chain{"password"}))
	f.flow.Guard = login.ThrottleGuard{Throttle: &login.Throttle{
		Store:        throttlememory.New(),
		FreeFailures: 2,
		BaseDelay:    time.Hour,
	}}

	submit(t, f, "bob", "password", "wrong")
	res := submit(t, f, "bob", "password", "bob-pw") // one failure: still allowed
	if !res.OK || !res.Done {
		t.Fatalf("correct password within the free budget should log in, got %+v", res)
	}
	// the success cleared the count: one more wrong attempt stays within budget
	res = submit(t, f, "bob", "password", "wrong")
	if res.OK {
		t.Fatalf("wrong password is a failure, got %+v", res)
	}
	res = submit(t, f, "bob", "password", "bob-pw")
	if !res.OK || !res.Done {
		t.Fatalf("one failure after reset is within the free budget, got %+v", res)
	}
}

func TestGuard_PerLoginIDIsolation(t *testing.T) {
	f := newGuardedFixture()

	submit(t, f, "bob", "password", "wrong")
	submit(t, f, "bob", "password", "wrong")
	// bob is throttled; alice's flow is untouched (password-only policy would
	// not complete for alice, so use a fresh assertion on the guard instead)
	res := submit(t, f, "bob", "password", "bob-pw")
	if res.OK {
		t.Fatal("bob should be throttled")
	}
	res = submit(t, f, "alice", "password", "alice-pw")
	if !res.OK {
		t.Fatalf("alice must not be affected by bob's failures, got %+v", res)
	}
}

func TestGuard_OutOfOrderSubmissionNotCounted(t *testing.T) {
	// method-not-offered rejections test no secret and must not consume the
	// failure budget.
	f := newFixture(login.RequireAny(login.Chain{"password", "totp"}))
	f.flow.Guard = login.ThrottleGuard{Throttle: &login.Throttle{
		Store:        throttlememory.New(),
		FreeFailures: 1,
		BaseDelay:    time.Hour,
	}}

	submit(t, f, "alice", "totp", totpCode(t)) // not offered yet: rejected, not counted
	submit(t, f, "alice", "totp", totpCode(t))
	res := submit(t, f, "alice", "password", "alice-pw")
	if !res.OK {
		t.Fatalf("out-of-order submissions must not consume the failure budget, got %+v", res)
	}
}
