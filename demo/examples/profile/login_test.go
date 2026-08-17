package profile

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
	"github.com/pquerna/otp/totp"
)

func TestProfileLoginOneStepNoTOTP(t *testing.T) {
	handler, users, _ := newProfileHandler(t)
	uid := "onestep@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	w := demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/profile/" {
		t.Errorf("want redirect /profile/, got %q", w.Header().Get("Location"))
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie")
	}
}

func TestProfileLoginTwoStepTOTP(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "twostep@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	secret := enableTOTP(t, mfaSvc, users, uid)

	w := demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("password step: want 200 (2FA page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/profile/login/2fa") {
		t.Errorf("expected the 2FA form in the body")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set at the password step")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w = demotest.PostForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {code}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("2FA step: want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/profile/" {
		t.Errorf("want redirect /profile/, got %q", w.Header().Get("Location"))
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie after 2FA")
	}
}

func TestProfileLoginTwoStepWrongCode(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "wrongcode@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	enableTOTP(t, mfaSvc, users, uid)
	// establish the pending login (password step)
	_ = demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)

	w := demotest.PostForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {"000000"}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("wrong code: want 200 (re-render), got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a wrong code")
	}
}
