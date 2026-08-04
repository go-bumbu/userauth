package register_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/register"
	"github.com/go-bumbu/userauth/flow/register/invite"
	invitememory "github.com/go-bumbu/userauth/flow/register/invite/memory"
	"github.com/go-bumbu/userauth/flow/register/pendingstore/memory"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
)

// fakeUsers is a UserGetter over a mutable set of login IDs.
type fakeUsers struct {
	existing map[string]bool
}

func (u *fakeUsers) GetUser(id string) (userauth.User, error) {
	if u.existing[id] {
		return userauth.User{Id: id, Enabled: true}, nil
	}
	return userauth.User{}, userauth.ErrUserNotFound
}

// captureCreator records created users; optionally fails.
type captureCreator struct {
	users []register.NewUser
	err   error
}

func (c *captureCreator) CreateVerifiedUser(u register.NewUser) error {
	if c.err != nil {
		return c.err
	}
	c.users = append(c.users, u)
	return nil
}

// captureDeliverer records the last delivered code; optionally fails.
type captureDeliverer struct {
	to    string
	code  string
	calls int
	err   error
}

func (d *captureDeliverer) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	d.calls++
	if d.err != nil {
		return d.err
	}
	d.to = to
	d.code = code
	return nil
}

// captureLogin records LoginUser calls.
type captureLogin struct {
	userID string
	calls  int
	err    error
}

func (l *captureLogin) LoginUser(_ *http.Request, _ http.ResponseWriter, userID string, _ bool) error {
	if l.err != nil {
		return l.err
	}
	l.userID = userID
	l.calls++
	return nil
}

type fixture struct {
	flow      *register.Flow
	users     *fakeUsers
	creator   *captureCreator
	deliverer *captureDeliverer
	session   *captureLogin
	invites   *invite.Service
	pending   *memory.Store
}

func newFixture(mod func(*fixture)) *fixture {
	f := &fixture{
		users:     &fakeUsers{existing: map[string]bool{"taken": true}},
		creator:   &captureCreator{},
		deliverer: &captureDeliverer{},
		session:   &captureLogin{},
		invites:   invite.New(invitememory.New(), invite.Opts{}),
		pending:   memory.New(),
	}
	f.flow = &register.Flow{
		Users:   f.users,
		Creator: f.creator,
		Pending: f.pending,
	}
	if mod != nil {
		mod(f)
	}
	return f
}

func withEmailCheck(f *fixture) {
	codes := verificationcode.NewService(csmemory.New(), verificationcode.Opts{})
	f.flow.Checks = append(f.flow.Checks, register.EmailCheck{Codes: codes, Deliver: f.deliverer})
}

func withInviteCheck(f *fixture) {
	f.flow.Checks = append(f.flow.Checks, register.InviteCheck{Invites: f.invites})
}

func start(t *testing.T, f *fixture, in register.StartInput) (register.Result, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	return f.flow.Start(r, httptest.NewRecorder(), in)
}

func verify(t *testing.T, f *fixture, loginID, checkID, input string) (register.Result, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/register/verify", nil)
	return f.flow.VerifyCheck(r, httptest.NewRecorder(), loginID, checkID, input)
}

func TestOpenRegistration(t *testing.T) {
	t.Run("creates the user immediately", func(t *testing.T) {
		f := newFixture(nil)
		res, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || !res.Done {
			t.Fatalf("want OK+Done, got %+v", res)
		}
		if len(f.creator.users) != 1 {
			t.Fatalf("want 1 created user, got %d", len(f.creator.users))
		}
		u := f.creator.users[0]
		if u.LoginID != "alice" || u.EmailVerified {
			t.Errorf("unexpected created user %+v", u)
		}
		if ok, _ := hashutil.VerifyPassword("pw", u.PasswordHash); !ok {
			t.Error("stored hash does not verify against the password")
		}
	})

	t.Run("trims the login ID", func(t *testing.T) {
		f := newFixture(nil)
		if _, err := start(t, f, register.StartInput{LoginID: "  alice  ", Password: "pw"}); err != nil {
			t.Fatal(err)
		}
		if f.creator.users[0].LoginID != "alice" {
			t.Errorf("want trimmed login ID, got %q", f.creator.users[0].LoginID)
		}
	})

	t.Run("existing user yields ErrUserExists", func(t *testing.T) {
		f := newFixture(nil)
		_, err := start(t, f, register.StartInput{LoginID: "taken", Password: "pw"})
		if !errors.Is(err, register.ErrUserExists) {
			t.Fatalf("want ErrUserExists, got %v", err)
		}
	})

}

func TestOpenRegistrationValidation(t *testing.T) {
	t.Run("empty login and empty password are validation errors", func(t *testing.T) {
		f := newFixture(nil)
		var vErr *register.ValidationError
		if _, err := start(t, f, register.StartInput{Password: "pw"}); !errors.As(err, &vErr) {
			t.Fatalf("want ValidationError for empty login, got %v", err)
		}
		if _, err := start(t, f, register.StartInput{LoginID: "alice"}); !errors.As(err, &vErr) {
			t.Fatalf("want ValidationError for empty password, got %v", err)
		}
	})

	t.Run("login ID format is enforced", func(t *testing.T) {
		f := newFixture(func(f *fixture) { f.flow.UsernameFormat = userauth.UsernameFormatEmail })
		var vErr *register.ValidationError
		if _, err := start(t, f, register.StartInput{LoginID: "not-an-email", Password: "pw"}); !errors.As(err, &vErr) {
			t.Fatalf("want ValidationError for non-email login, got %v", err)
		}
		res, err := start(t, f, register.StartInput{LoginID: "a@example.com", Password: "pw"})
		if err != nil || !res.Done {
			t.Fatalf("want email login accepted, got res=%+v err=%v", res, err)
		}
		if f.creator.users[0].Email != "a@example.com" {
			t.Errorf("want email defaulted from login ID, got %q", f.creator.users[0].Email)
		}
	})

	t.Run("custom password validator is applied", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			f.flow.Password = register.PasswordValidatorFunc(func(pw string) error {
				if len(pw) < 8 {
					return errors.New("password must be at least 8 characters")
				}
				return nil
			})
		})
		var vErr *register.ValidationError
		_, err := start(t, f, register.StartInput{LoginID: "alice", Password: "short"})
		if !errors.As(err, &vErr) {
			t.Fatalf("want ValidationError, got %v", err)
		}
		if vErr.Msg != "password must be at least 8 characters" {
			t.Errorf("want validator message surfaced, got %q", vErr.Msg)
		}
	})

}

func TestOpenRegistrationSession(t *testing.T) {
	t.Run("auto-login when a session creator is configured", func(t *testing.T) {
		f := newFixture(func(f *fixture) { f.flow.Session = f.session })
		if _, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"}); err != nil {
			t.Fatal(err)
		}
		if f.session.calls != 1 || f.session.userID != "alice" {
			t.Errorf("want exactly one auto-login for alice, got %+v", f.session)
		}
	})

	t.Run("session failure still reports Done", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			f.session.err = errors.New("session store down")
			f.flow.Session = f.session
		})
		res, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"})
		if err != nil || !res.Done {
			t.Fatalf("want Done despite session failure, got res=%+v err=%v", res, err)
		}
	})

	t.Run("missing required config errors", func(t *testing.T) {
		f := newFixture(func(f *fixture) { f.flow.Creator = nil })
		if _, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"}); err == nil {
			t.Fatal("want error for missing Creator")
		}
	})
}

// emailInput is the canonical start input for the email-verification tests.
var emailInput = register.StartInput{LoginID: "alice", Password: "pw", Email: "alice@example.com"}

func TestEmailVerification(t *testing.T) {
	input := emailInput

	t.Run("full round trip", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		res, err := start(t, f, input)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || res.Done {
			t.Fatalf("want OK pending, got %+v", res)
		}
		if len(res.Next) != 1 || res.Next[0] != register.CheckEmail {
			t.Fatalf("want next=[email], got %v", res.Next)
		}
		if f.deliverer.to != "alice@example.com" || f.deliverer.code == "" {
			t.Fatalf("want code delivered to the email, got %+v", f.deliverer)
		}
		if len(f.creator.users) != 0 {
			t.Fatal("user must not be created before verification")
		}

		res, err = verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || !res.Done {
			t.Fatalf("want OK+Done, got %+v", res)
		}
		if len(f.creator.users) != 1 {
			t.Fatalf("want 1 created user, got %d", len(f.creator.users))
		}
		u := f.creator.users[0]
		if u.Email != "alice@example.com" || !u.EmailVerified {
			t.Errorf("want verified email on created user, got %+v", u)
		}
	})

	t.Run("wrong code is rejected uniformly", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		res, err := verify(t, f, "alice", register.CheckEmail, "000000")
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("want rejection, got %+v", res)
		}
		if len(f.creator.users) != 0 {
			t.Fatal("user must not be created on wrong code")
		}
	})

}

func TestEmailVerificationPendingState(t *testing.T) {
	input := emailInput

	t.Run("verify without pending registration is rejected uniformly", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		res, err := verify(t, f, "nobody", register.CheckEmail, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("want rejection, got %+v", res)
		}
	})

	t.Run("expired pending registration is rejected", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		// age the pending registration past its expiry
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		reg, err := f.pending.Get(r, "alice")
		if err != nil {
			t.Fatal(err)
		}
		reg.ExpiresAt = time.Now().Add(-time.Second)
		if err := f.pending.Set(r, httptest.NewRecorder(), reg); err != nil {
			t.Fatal(err)
		}
		res, err := verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("want rejection of expired registration, got %+v", res)
		}
	})

	t.Run("restart overwrites the pending registration", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		oldCode := f.deliverer.code
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		if oldCode == f.deliverer.code {
			t.Fatal("want a fresh code after restart")
		}
		// the old code was replaced in the code store
		res, err := verify(t, f, "alice", register.CheckEmail, oldCode)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatal("want old code rejected after restart")
		}
		res, err = verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil || !res.Done {
			t.Fatalf("want fresh code accepted, got res=%+v err=%v", res, err)
		}
	})

	t.Run("missing email is a validation error", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		var vErr *register.ValidationError
		_, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"})
		if !errors.As(err, &vErr) {
			t.Fatalf("want ValidationError for missing email, got %v", err)
		}
	})

}

func TestEmailVerificationDeliveryAndConfig(t *testing.T) {
	input := emailInput

	t.Run("delivery failure is logged not returned", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			withEmailCheck(f)
			f.deliverer.err = errors.New("smtp down")
		})
		res, err := start(t, f, input)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || res.Done {
			t.Fatalf("want pending result despite delivery failure, got %+v", res)
		}
	})

	t.Run("resend via Initiate", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/register/request-code", nil)
		if err := f.flow.Initiate(r, "alice", register.CheckEmail); err != nil {
			t.Fatal(err)
		}
		if f.deliverer.calls != 2 {
			t.Errorf("want 2 deliveries, got %d", f.deliverer.calls)
		}
		// the re-sent code completes the registration
		res, err := verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil || !res.Done {
			t.Fatalf("want resent code accepted, got res=%+v err=%v", res, err)
		}
	})

	t.Run("initiate without pending registration is a silent no-op", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		r := httptest.NewRequest(http.MethodPost, "/register/request-code", nil)
		if err := f.flow.Initiate(r, "nobody", register.CheckEmail); err != nil {
			t.Fatal(err)
		}
		if f.deliverer.calls != 0 {
			t.Errorf("want no delivery, got %d", f.deliverer.calls)
		}
	})

	t.Run("unknown check is misconfiguration", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		if _, err := verify(t, f, "alice", "sms", "123"); err == nil {
			t.Fatal("want error for unregistered check")
		}
	})

	t.Run("round-trip check without pending store is an error", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			withEmailCheck(f)
			f.flow.Pending = nil
		})
		if _, err := start(t, f, input); err == nil {
			t.Fatal("want error for nil Pending with round-trip check")
		}
	})

	t.Run("username taken while pending yields ErrUserExists at verify", func(t *testing.T) {
		f := newFixture(withEmailCheck)
		if _, err := start(t, f, input); err != nil {
			t.Fatal(err)
		}
		f.users.existing["alice"] = true // someone registered alice meanwhile
		_, err := verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if !errors.Is(err, register.ErrUserExists) {
			t.Fatalf("want ErrUserExists, got %v", err)
		}
	})
}

// issue creates an invite on the fixture's service and returns its code.
func issue(t *testing.T, f *fixture, opts invite.IssueOpts) string {
	t.Helper()
	inv, err := f.invites.Issue(opts)
	if err != nil {
		t.Fatal(err)
	}
	return inv.Code
}

func TestInviteRegistration(t *testing.T) {
	t.Run("valid invite registers immediately and consumes", func(t *testing.T) {
		f := newFixture(withInviteCheck)
		code := issue(t, f, invite.IssueOpts{})
		res, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw", InviteCode: code})
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || !res.Done {
			t.Fatalf("want OK+Done, got %+v", res)
		}
		if len(f.creator.users) != 1 {
			t.Fatalf("want 1 created user, got %d", len(f.creator.users))
		}
		if ok, _ := f.invites.Validate(code, ""); ok {
			t.Error("want single-use invite consumed")
		}
	})

	t.Run("invalid invite is rejected uniformly", func(t *testing.T) {
		f := newFixture(withInviteCheck)
		res, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw", InviteCode: "bogus"})
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("want rejection, got %+v", res)
		}
		if len(f.creator.users) != 0 {
			t.Fatal("user must not be created with a bad invite")
		}
	})

	t.Run("invite consumed while pending aborts at finish", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			withInviteCheck(f)
			withEmailCheck(f)
		})
		code := issue(t, f, invite.IssueOpts{}) // single use
		in := register.StartInput{LoginID: "alice", Password: "pw", Email: "alice@example.com", InviteCode: code}
		if _, err := start(t, f, in); err != nil {
			t.Fatal(err)
		}
		// the invite gets consumed elsewhere while alice verifies her email
		if ok, _ := f.invites.Consume(code, ""); !ok {
			t.Fatal("test setup: consume failed")
		}
		res, err := verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatalf("want abort when invite is gone, got %+v", res)
		}
		if len(f.creator.users) != 0 {
			t.Fatal("user must not be created when the invite is gone")
		}
		// pending state was cleared: the same verify now finds nothing
		res, _ = verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if res.OK {
			t.Fatal("want pending registration cleared after finalize failure")
		}
	})

	t.Run("email-bound invite", func(t *testing.T) {
		f := newFixture(withInviteCheck)
		code := issue(t, f, invite.IssueOpts{Email: "vip@example.com"})
		res, err := start(t, f, register.StartInput{LoginID: "mallory", Password: "pw", Email: "mallory@example.com", InviteCode: code})
		if err != nil || res.OK {
			t.Fatalf("want rejection for wrong email, got res=%+v err=%v", res, err)
		}
		res, err = start(t, f, register.StartInput{LoginID: "vip", Password: "pw", Email: "vip@example.com", InviteCode: code})
		if err != nil || !res.Done {
			t.Fatalf("want bound email accepted, got res=%+v err=%v", res, err)
		}
	})

}

func TestInviteRegistrationWithEmailCheck(t *testing.T) {
	t.Run("invite and email verification combined", func(t *testing.T) {
		f := newFixture(func(f *fixture) {
			withInviteCheck(f)
			withEmailCheck(f)
		})
		code := issue(t, f, invite.IssueOpts{})
		in := register.StartInput{LoginID: "alice", Password: "pw", Email: "alice@example.com", InviteCode: code}
		res, err := start(t, f, in)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK || res.Done {
			t.Fatalf("want pending after start, got %+v", res)
		}
		if len(res.Next) != 1 || res.Next[0] != register.CheckEmail {
			t.Fatalf("want only email left (invite pre-verified), got %v", res.Next)
		}
		res, err = verify(t, f, "alice", register.CheckEmail, f.deliverer.code)
		if err != nil || !res.Done {
			t.Fatalf("want Done after email verification, got res=%+v err=%v", res, err)
		}
		u := f.creator.users[0]
		if !u.EmailVerified {
			t.Error("want email marked verified")
		}
		if ok, _ := f.invites.Validate(code, ""); ok {
			t.Error("want invite consumed at creation")
		}
	})
}

func TestCreatorConflict(t *testing.T) {
	f := newFixture(func(f *fixture) {
		f.creator.err = register.ErrUserExists
	})
	_, err := start(t, f, register.StartInput{LoginID: "alice", Password: "pw"})
	if !errors.Is(err, register.ErrUserExists) {
		t.Fatalf("want ErrUserExists passed through from creator, got %v", err)
	}
}
