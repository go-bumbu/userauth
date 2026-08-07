package invite_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/register/invite"
	"github.com/go-bumbu/userauth/flow/register/invite/memory"
)

func newService(t *testing.T, opts invite.Opts) *invite.Service {
	t.Helper()
	return invite.New(memory.New(), opts)
}

func TestIssueDefaults(t *testing.T) {
	svc := newService(t, invite.Opts{})
	inv, err := svc.Issue(invite.IssueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Code) != invite.DefaultCodeLength {
		t.Errorf("want code length %d, got %d", invite.DefaultCodeLength, len(inv.Code))
	}
	if inv.UsesLeft != 1 {
		t.Errorf("want 1 use by default, got %d", inv.UsesLeft)
	}
	if !inv.ExpiresAt.IsZero() {
		t.Errorf("want no expiry by default, got %v", inv.ExpiresAt)
	}
}

func TestIssueCustomLength(t *testing.T) {
	svc := newService(t, invite.Opts{CodeLength: 20})
	inv, err := svc.Issue(invite.IssueOpts{Uses: 5, Note: "team A"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Code) != 20 {
		t.Errorf("want code length 20, got %d", len(inv.Code))
	}
	if inv.UsesLeft != 5 {
		t.Errorf("want 5 uses, got %d", inv.UsesLeft)
	}
	if inv.Note != "team A" {
		t.Errorf("want note kept, got %q", inv.Note)
	}
}

func TestValidateAndConsume(t *testing.T) {
	tcs := []struct {
		name  string
		issue invite.IssueOpts
		code  func(issued string) string // code submitted; default = issued
		email string
		want  bool
	}{
		{name: "valid single use", issue: invite.IssueOpts{}, want: true},
		{name: "unknown code", issue: invite.IssueOpts{}, code: func(string) string { return "nope" }, want: false},
		{name: "expired", issue: invite.IssueOpts{ExpiresAt: time.Now().Add(-time.Minute)}, want: false},
		{name: "email bound match", issue: invite.IssueOpts{Email: "a@example.com"}, email: "a@example.com", want: true},
		{name: "email bound mismatch", issue: invite.IssueOpts{Email: "a@example.com"}, email: "b@example.com", want: false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService(t, invite.Opts{})
			inv, err := svc.Issue(tc.issue)
			if err != nil {
				t.Fatal(err)
			}
			code := inv.Code
			if tc.code != nil {
				code = tc.code(inv.Code)
			}

			ok, err := svc.Validate(code, tc.email)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Errorf("Validate: want %v, got %v", tc.want, ok)
			}
			ok, err = svc.Consume(code, tc.email)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Errorf("Consume: want %v, got %v", tc.want, ok)
			}
		})
	}
}

func TestConsumeExhausts(t *testing.T) {
	svc := newService(t, invite.Opts{})
	inv, err := svc.Issue(invite.IssueOpts{Uses: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		ok, err := svc.Consume(inv.Code, "")
		if err != nil || !ok {
			t.Fatalf("consume %d: want ok, got ok=%v err=%v", i+1, ok, err)
		}
	}
	ok, err := svc.Consume(inv.Code, "")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("want exhausted invite to be rejected")
	}
	if ok, _ := svc.Validate(inv.Code, ""); ok {
		t.Error("want exhausted invite to fail validation")
	}
}

func TestRevoke(t *testing.T) {
	svc := newService(t, invite.Opts{})
	inv, err := svc.Issue(invite.IssueOpts{Uses: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(inv.Code); err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.Validate(inv.Code, ""); ok {
		t.Error("want revoked invite to fail validation")
	}
	if ok, _ := svc.Consume(inv.Code, ""); ok {
		t.Error("want revoked invite to fail consumption")
	}
	if err := svc.Revoke("unknown"); err == nil {
		t.Error("want error revoking unknown code")
	}
}

func TestList(t *testing.T) {
	svc := newService(t, invite.Opts{})
	for i := 0; i < 3; i++ {
		if _, err := svc.Issue(invite.IssueOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Errorf("want 3 invites, got %d", len(list))
	}
}
