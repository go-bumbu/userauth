package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/pquerna/otp/totp"
)

// postProfileForm posts a urlencoded form to the profile demo handler, attaching cookies.
func postProfileForm(handler http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestProfileLoginOneStepNoTOTP(t *testing.T) {
	handler := profileDemo()
	uid := "onestep@example.com"
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	w := postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
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
	handler := profileDemo()
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- test TOTP secret
	uid := "twostep@example.com"
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := dbUserMgr.SetTOTP(uid, userauth.TOTPData{Secret: secret, Enabled: true}); err != nil {
		t.Fatalf("set totp: %v", err)
	}

	w := postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
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
	w = postProfileForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {code}}, nil)
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
	handler := profileDemo()
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- test TOTP secret
	uid := "wrongcode@example.com"
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := dbUserMgr.SetTOTP(uid, userauth.TOTPData{Secret: secret, Enabled: true}); err != nil {
		t.Fatalf("set totp: %v", err)
	}
	// establish the pending login (password step)
	_ = postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)

	w := postProfileForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {"000000"}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("wrong code: want 200 (re-render), got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a wrong code")
	}
}
