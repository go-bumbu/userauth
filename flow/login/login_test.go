package login_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/login"
	"github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/pquerna/otp/totp"
)

const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// captureDeliverer records the last delivered code instead of sending it.
type captureDeliverer struct {
	code string
}

func (d *captureDeliverer) Deliver(_ context.Context, _ string, code string, _ time.Time) error {
	d.code = code
	return nil
}

// captureLogin records LoginUser calls instead of creating a real session.
type captureLogin struct {
	userID string
	keep   bool
	calls  int
}

func (l *captureLogin) LoginUser(_ *http.Request, _ http.ResponseWriter, userID string, keep bool) error {
	l.userID = userID
	l.keep = keep
	l.calls++
	return nil
}

type fixture struct {
	flow      *login.Flow
	users     *staticusers.Users
	deliverer *captureDeliverer
	session   *captureLogin
}

// newFixture builds a Flow with password, TOTP and email methods over two
// users: "alice" (password+TOTP enrolled) and "bob" (password only, disabled
// twin "carol"). The policy is supplied by the test.
func newFixture(policy login.Policy) *fixture {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "alice", HashPw: userauth.MustHashPw("alice-pw"), Enabled: true, TOTPSecret: totpSecret},
		{Id: "bob", HashPw: userauth.MustHashPw("bob-pw"), Enabled: true},
		{Id: "carol", HashPw: userauth.MustHashPw("carol-pw"), Enabled: false},
	}}
	codes := verificationcode.NewService(csmemory.New(), verificationcode.Opts{})
	deliverer := &captureDeliverer{}
	session := &captureLogin{}
	flow := &login.Flow{
		Users: users,
		Methods: []login.Method{
			login.PasswordMethod{Users: users},
			login.TOTPMethod{TOTP: users},
			login.EmailCodeMethod(codes, deliverer),
		},
		Policy:   policy,
		Attempts: memory.New(),
		Session:  session,
	}
	return &fixture{flow: flow, users: users, deliverer: deliverer, session: session}
}

func submit(t *testing.T, f *fixture, userID, method, input string) login.Result {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	res, err := f.flow.Submit(r, httptest.NewRecorder(), userID, method, input, false)
	if err != nil {
		t.Fatalf("Submit(%s, %s): %v", userID, method, err)
	}
	return res
}

func initiate(t *testing.T, f *fixture, userID, method string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	if err := f.flow.Initiate(r, userID, method); err != nil {
		t.Fatalf("Initiate(%s, %s): %v", userID, method, err)
	}
}

func totpCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestFlowSingleFactor(t *testing.T) {
	f := newFixture(login.RequireAny(login.Chain{"password"}))

	t.Run("valid password logs in", func(t *testing.T) {
		res := submit(t, f, "bob", "password", "bob-pw")
		if !res.OK || !res.Done {
			t.Fatalf("want OK+Done, got %+v", res)
		}
		if f.session.userID != "bob" || f.session.calls != 1 {
			t.Errorf("session: want 1 login for bob, got %+v", f.session)
		}
	})

	t.Run("wrong password, unknown user and disabled user are indistinguishable", func(t *testing.T) {
		f := newFixture(login.RequireAny(login.Chain{"password"}))
		for name, in := range map[string][2]string{
			"wrong password": {"bob", "nope"},
			"unknown user":   {"ghost", "whatever"},
			"disabled user":  {"carol", "carol-pw"},
		} {
			res := submit(t, f, in[0], "password", in[1])
			if res.OK || res.Done || res.Next != nil {
				t.Errorf("%s: want zero Result, got %+v", name, res)
			}
		}
		if f.session.calls != 0 {
			t.Error("no session must be created")
		}
	})

	t.Run("unregistered method is an internal error", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		_, err := f.flow.Submit(r, httptest.NewRecorder(), "bob", "sms", "123", false)
		if err == nil {
			t.Fatal("want error for unregistered method")
		}
	})
}

func TestFlowPasswordPlusTOTP(t *testing.T) {
	policy := login.RequireAny(login.Chain{"password", "totp"})

	t.Run("password alone is not enough", func(t *testing.T) {
		f := newFixture(policy)
		res := submit(t, f, "alice", "password", "alice-pw")
		if !res.OK || res.Done {
			t.Fatalf("want OK, not Done, got %+v", res)
		}
		if len(res.Next) != 1 || res.Next[0] != "totp" {
			t.Fatalf("want Next=[totp], got %v", res.Next)
		}
		if f.session.calls != 0 {
			t.Error("no session before TOTP")
		}

		res = submit(t, f, "alice", "totp", totpCode(t))
		if !res.OK || !res.Done {
			t.Fatalf("want OK+Done after TOTP, got %+v", res)
		}
		if f.session.userID != "alice" {
			t.Errorf("session for %q, want alice", f.session.userID)
		}
	})

	t.Run("TOTP before password is rejected", func(t *testing.T) {
		f := newFixture(policy)
		res := submit(t, f, "alice", "totp", totpCode(t))
		if res.OK {
			t.Fatalf("TOTP must not count before password, got %+v", res)
		}
		if f.session.calls != 0 {
			t.Error("no session must be created")
		}
	})

	t.Run("wrong TOTP after valid password keeps the attempt open", func(t *testing.T) {
		f := newFixture(policy)
		submit(t, f, "alice", "password", "alice-pw")
		res := submit(t, f, "alice", "totp", "000000")
		if res.OK {
			t.Fatalf("wrong TOTP accepted: %+v", res)
		}
		// the password factor is still satisfied; a correct TOTP completes
		res = submit(t, f, "alice", "totp", totpCode(t))
		if !res.OK || !res.Done {
			t.Fatalf("valid TOTP after retry should complete, got %+v", res)
		}
	})

	t.Run("user disabled mid-flow is rejected", func(t *testing.T) {
		f := newFixture(policy)
		submit(t, f, "alice", "password", "alice-pw")
		f.users.Users[0].Enabled = false
		res := submit(t, f, "alice", "totp", totpCode(t))
		if res.OK || f.session.calls != 0 {
			t.Fatalf("disabled user completed login: %+v", res)
		}
	})
}

func TestFlowEmailPlusTOTP(t *testing.T) {
	// The composition that motivated the package: passwordless email code
	// as first factor, TOTP as second.
	policy := login.RequireAny(login.Chain{"email", "totp"})
	f := newFixture(policy)

	initiate(t, f, "alice", "email")
	if f.deliverer.code == "" {
		t.Fatal("no email code delivered")
	}

	res := submit(t, f, "alice", "email", f.deliverer.code)
	if !res.OK || res.Done {
		t.Fatalf("email code alone must not complete, got %+v", res)
	}
	if len(res.Next) != 1 || res.Next[0] != "totp" {
		t.Fatalf("want Next=[totp], got %v", res.Next)
	}

	res = submit(t, f, "alice", "totp", totpCode(t))
	if !res.OK || !res.Done {
		t.Fatalf("want Done after TOTP, got %+v", res)
	}
	if f.session.userID != "alice" || f.session.calls != 1 {
		t.Errorf("want one session for alice, got %+v", f.session)
	}
}

func TestFlowAlternativeChains(t *testing.T) {
	// password+TOTP, or email code alone.
	policy := login.RequireAny(login.Chain{"password", "totp"}, login.Chain{"email"})

	t.Run("email chain completes alone", func(t *testing.T) {
		f := newFixture(policy)
		initiate(t, f, "bob", "email")
		res := submit(t, f, "bob", "email", f.deliverer.code)
		if !res.OK || !res.Done {
			t.Fatalf("email chain should complete alone, got %+v", res)
		}
	})

	t.Run("password chain still requires TOTP", func(t *testing.T) {
		f := newFixture(policy)
		res := submit(t, f, "alice", "password", "alice-pw")
		if !res.OK || res.Done {
			t.Fatalf("want OK, not Done, got %+v", res)
		}
	})
}

func TestFlowInitiate(t *testing.T) {
	policy := login.RequireAny(login.Chain{"email"})

	t.Run("unknown and disabled users get no code, no error", func(t *testing.T) {
		f := newFixture(policy)
		initiate(t, f, "ghost", "email")
		initiate(t, f, "carol", "email")
		if f.deliverer.code != "" {
			t.Error("no code must be delivered for unknown/disabled users")
		}
	})

	t.Run("method not offered by policy gets no code", func(t *testing.T) {
		f := newFixture(login.RequireAny(login.Chain{"password"}))
		initiate(t, f, "bob", "email")
		if f.deliverer.code != "" {
			t.Error("no code must be delivered when the policy does not offer email")
		}
	})

	t.Run("method without initiation support is an error", func(t *testing.T) {
		f := newFixture(policy)
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		if err := f.flow.Initiate(r, "bob", "password"); err == nil {
			t.Fatal("want error for non-initiable method")
		}
	})
}

func TestFlowAttemptExpiry(t *testing.T) {
	policy := login.RequireAny(login.Chain{"password", "totp"})
	f := newFixture(policy)
	f.flow.Expiry = 30 * time.Millisecond

	submit(t, f, "alice", "password", "alice-pw")
	time.Sleep(50 * time.Millisecond)

	// The attempt expired: TOTP is no longer offered, password must be redone.
	res := submit(t, f, "alice", "totp", totpCode(t))
	if res.OK {
		t.Fatalf("TOTP on an expired attempt must be rejected, got %+v", res)
	}
	res = submit(t, f, "alice", "password", "alice-pw")
	if !res.OK || res.Done {
		t.Fatalf("fresh attempt should restart at password, got %+v", res)
	}
}

func TestFlowKeepLoggedIn(t *testing.T) {
	policy := login.RequireAny(login.Chain{"password", "totp"})
	f := newFixture(policy)
	r := httptest.NewRequest(http.MethodPost, "/login", nil)

	// keepLoggedIn is captured on the first factor; the second submission's
	// value is ignored.
	if _, err := f.flow.Submit(r, httptest.NewRecorder(), "alice", "password", "alice-pw", true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.flow.Submit(r, httptest.NewRecorder(), "alice", "totp", totpCode(t), false); err != nil {
		t.Fatal(err)
	}
	if f.session.calls != 1 || !f.session.keep {
		t.Errorf("want session with keepLoggedIn=true from first factor, got %+v", f.session)
	}
}

func TestFlowSecondFactorAfter(t *testing.T) {
	// SecondFactorAfter("password", provider) implements the classic 2FA
	// semantics: alice (TOTP enrolled) needs a second factor, bob does not.
	f := newFixture(nil)
	f.flow.Policy = login.SecondFactorAfter("password", f.users)

	res := submit(t, f, "bob", "password", "bob-pw")
	if !res.OK || !res.Done {
		t.Fatalf("bob has no 2FA, password should complete, got %+v", res)
	}

	res = submit(t, f, "alice", "password", "alice-pw")
	if !res.OK || res.Done {
		t.Fatalf("alice has TOTP enrolled, want 2FA step, got %+v", res)
	}
	if len(res.Next) != 1 || res.Next[0] != "totp" {
		t.Fatalf("want Next=[totp], got %v", res.Next)
	}
	res = submit(t, f, "alice", "totp", totpCode(t))
	if !res.OK || !res.Done {
		t.Fatalf("TOTP should complete alice's login, got %+v", res)
	}
}
