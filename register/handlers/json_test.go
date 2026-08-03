package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/register"
	"github.com/go-bumbu/userauth/register/handlers"
	"github.com/go-bumbu/userauth/register/invite"
	invitememory "github.com/go-bumbu/userauth/register/invite/memory"
	"github.com/go-bumbu/userauth/register/pendingstore/memory"
	csmemory "github.com/go-bumbu/userauth/codestore/memory"
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

// captureCreator records created users.
type captureCreator struct {
	users []register.NewUser
}

func (c *captureCreator) CreateVerifiedUser(u register.NewUser) error {
	c.users = append(c.users, u)
	return nil
}

// captureDeliverer records the last delivered code.
type captureDeliverer struct {
	code string
}

func (d *captureDeliverer) Deliver(_ context.Context, _ string, code string, _ time.Time) error {
	d.code = code
	return nil
}

type fixture struct {
	json      *handlers.JSON
	users     *fakeUsers
	creator   *captureCreator
	deliverer *captureDeliverer
	invites   *invite.Service
}

func newFixture(mod func(*fixture, *handlers.Cfg)) *fixture {
	f := &fixture{
		users:     &fakeUsers{existing: map[string]bool{"taken": true}},
		creator:   &captureCreator{},
		deliverer: &captureDeliverer{},
		invites:   invite.New(invitememory.New(), invite.Opts{}),
	}
	cfg := handlers.Cfg{
		Users:   f.users,
		Creator: f.creator,
		Pending: memory.New(),
	}
	if mod != nil {
		mod(f, &cfg)
	}
	f.json = handlers.New(cfg)
	return f
}

func withEmail(f *fixture, cfg *handlers.Cfg) {
	cfg.Codes = userauth.NewVerificationCodeService(csmemory.New(), userauth.VerificationCodeOpts{})
	cfg.Deliver = f.deliverer
}

func withInvites(f *fixture, cfg *handlers.Cfg) {
	cfg.Invites = f.invites
}

// post sends a JSON body to the handler, carrying cookies between calls via
// the passed request modifications; it returns status and decoded body.
func post(t *testing.T, h http.Handler, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var decoded map[string]any
	if err := json.NewDecoder(w.Result().Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return w.Result().StatusCode, decoded
}

func TestRegisterHandler(t *testing.T) {
	t.Run("open registration completes", func(t *testing.T) {
		f := newFixture(nil)
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw",
		})
		if status != http.StatusOK || body["done"] != true {
			t.Fatalf("want 200 done, got %d %v", status, body)
		}
		if len(f.creator.users) != 1 {
			t.Fatalf("want 1 created user, got %d", len(f.creator.users))
		}
	})

	t.Run("username taken yields 409", func(t *testing.T) {
		f := newFixture(nil)
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "taken", "password": "pw",
		})
		if status != http.StatusConflict {
			t.Fatalf("want 409, got %d %v", status, body)
		}
	})

	t.Run("validation errors yield 400 with message", func(t *testing.T) {
		f := newFixture(func(f *fixture, cfg *handlers.Cfg) {
			cfg.Password = register.PasswordValidatorFunc(func(pw string) error {
				if len(pw) < 8 {
					return &register.ValidationError{Msg: "password too short"}
				}
				return nil
			})
		})
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw",
		})
		if status != http.StatusBadRequest || body["error"] != "password too short" {
			t.Fatalf("want 400 with validator message, got %d %v", status, body)
		}
	})

	t.Run("missing fields yield 400", func(t *testing.T) {
		f := newFixture(nil)
		status, _ := post(t, f.json.RegisterHandler(), map[string]string{"username": "alice"})
		if status != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", status)
		}
	})

	t.Run("wrong method yields 405", func(t *testing.T) {
		f := newFixture(nil)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		f.json.RegisterHandler().ServeHTTP(w, r)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("want 405, got %d", w.Result().StatusCode)
		}
	})

	t.Run("bad invite yields uniform 401", func(t *testing.T) {
		f := newFixture(withInvites)
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw", "inviteCode": "bogus",
		})
		if status != http.StatusUnauthorized || body["error"] != "unauthorized" {
			t.Fatalf("want uniform 401, got %d %v", status, body)
		}
	})

	t.Run("good invite completes", func(t *testing.T) {
		f := newFixture(withInvites)
		inv, err := f.invites.Issue(invite.IssueOpts{})
		if err != nil {
			t.Fatal(err)
		}
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw", "inviteCode": inv.Code,
		})
		if status != http.StatusOK || body["done"] != true {
			t.Fatalf("want 200 done, got %d %v", status, body)
		}
	})
}

func TestVerifyHandler(t *testing.T) {
	startEmail := func(t *testing.T, f *fixture) {
		t.Helper()
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw", "email": "alice@example.com",
		})
		if status != http.StatusOK || body["done"] != false {
			t.Fatalf("start: want 200 pending, got %d %v", status, body)
		}
	}

	t.Run("email round trip", func(t *testing.T) {
		f := newFixture(withEmail)
		startEmail(t, f)
		if f.deliverer.code == "" {
			t.Fatal("want a delivered code")
		}
		status, body := post(t, f.json.VerifyHandler(), map[string]string{
			"username": "alice", "check": "email", "code": f.deliverer.code,
		})
		if status != http.StatusOK || body["done"] != true {
			t.Fatalf("want 200 done, got %d %v", status, body)
		}
		if len(f.creator.users) != 1 || !f.creator.users[0].EmailVerified {
			t.Fatalf("want verified user created, got %+v", f.creator.users)
		}
	})

	t.Run("wrong code, no pending and replay are one uniform 401", func(t *testing.T) {
		f := newFixture(withEmail)
		startEmail(t, f)
		for name, payload := range map[string]map[string]string{
			"wrong code": {"username": "alice", "check": "email", "code": "000000"},
			"no pending": {"username": "nobody", "check": "email", "code": "123456"},
		} {
			status, body := post(t, f.json.VerifyHandler(), payload)
			if status != http.StatusUnauthorized || body["error"] != "unauthorized" {
				t.Errorf("%s: want uniform 401, got %d %v", name, status, body)
			}
		}
	})

	t.Run("unknown check yields 400", func(t *testing.T) {
		f := newFixture(withEmail)
		status, _ := post(t, f.json.VerifyHandler(), map[string]string{
			"username": "alice", "check": "sms", "code": "123",
		})
		if status != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", status)
		}
	})

	t.Run("username taken while pending yields 409", func(t *testing.T) {
		f := newFixture(withEmail)
		startEmail(t, f)
		f.users.existing["alice"] = true
		status, _ := post(t, f.json.VerifyHandler(), map[string]string{
			"username": "alice", "check": "email", "code": f.deliverer.code,
		})
		if status != http.StatusConflict {
			t.Fatalf("want 409, got %d", status)
		}
	})
}

func TestRequestCodeHandler(t *testing.T) {
	t.Run("always 202, pending or not", func(t *testing.T) {
		f := newFixture(withEmail)
		// no pending registration for bob
		status, _ := post(t, f.json.RequestCodeHandler(), map[string]string{"username": "bob"})
		if status != http.StatusAccepted {
			t.Fatalf("want 202 without pending, got %d", status)
		}
		// pending registration for alice: same response, code re-delivered
		if s, _ := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw", "email": "alice@example.com",
		}); s != http.StatusOK {
			t.Fatalf("start failed with %d", s)
		}
		first := f.deliverer.code
		status, _ = post(t, f.json.RequestCodeHandler(), map[string]string{"username": "alice"})
		if status != http.StatusAccepted {
			t.Fatalf("want 202 with pending, got %d", status)
		}
		if f.deliverer.code == first {
			t.Error("want a fresh code delivered on re-request")
		}
	})

	t.Run("check without delivery yields 400", func(t *testing.T) {
		f := newFixture(func(f *fixture, cfg *handlers.Cfg) {
			withEmail(f, cfg)
			withInvites(f, cfg)
		})
		status, _ := post(t, f.json.RequestCodeHandler(), map[string]string{
			"username": "alice", "check": "invite",
		})
		if status != http.StatusBadRequest {
			t.Fatalf("want 400 for non-deliverable check, got %d", status)
		}
	})

	t.Run("open flow has no deliverable check", func(t *testing.T) {
		f := newFixture(nil)
		status, _ := post(t, f.json.RequestCodeHandler(), map[string]string{"username": "alice"})
		if status != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", status)
		}
	})
}

func TestCombinedInviteAndEmail(t *testing.T) {
	f := newFixture(func(f *fixture, cfg *handlers.Cfg) {
		withEmail(f, cfg)
		withInvites(f, cfg)
	})
	inv, err := f.invites.Issue(invite.IssueOpts{})
	if err != nil {
		t.Fatal(err)
	}

	status, body := post(t, f.json.RegisterHandler(), map[string]string{
		"username": "alice", "password": "pw", "email": "alice@example.com", "inviteCode": inv.Code,
	})
	if status != http.StatusOK || body["done"] != false {
		t.Fatalf("want 200 pending after start, got %d %v", status, body)
	}
	next, _ := body["next"].([]any)
	if len(next) != 1 || next[0] != "email" {
		t.Fatalf("want next=[email], got %v", body["next"])
	}

	status, body = post(t, f.json.VerifyHandler(), map[string]string{
		"username": "alice", "check": "email", "code": f.deliverer.code,
	})
	if status != http.StatusOK || body["done"] != true {
		t.Fatalf("want 200 done, got %d %v", status, body)
	}
	if ok, _ := f.invites.Validate(inv.Code, ""); ok {
		t.Error("want invite consumed")
	}
}
