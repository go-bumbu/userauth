package main

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

var totpSecretRe = regexp.MustCompile(`totp-secret">([A-Z2-7]+)<`)

// enrollTOTP logs in a fresh user (one-step), runs setup+confirm, and returns the
// login cookies and the confirm-response recorder. Fails the test on any error.
func enrollTOTP(t *testing.T, handler http.Handler, uid string) ([]*http.Cookie, string) {
	t.Helper()
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after one-step login")
	}
	sw := postProfileForm(handler, "/totp/setup", url.Values{}, cookies)
	if sw.Code != http.StatusOK {
		t.Fatalf("setup: want 200, got %d", sw.Code)
	}
	m := totpSecretRe.FindStringSubmatch(sw.Body.String())
	if m == nil {
		t.Fatalf("setup page missing secret; body=%s", sw.Body.String())
	}
	secret := m[1]
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	cw := postProfileForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	if cw.Code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", cw.Code)
	}
	return cookies, secret
}

func TestProfileTOTPEnroll(t *testing.T) {
	handler := profileDemo()
	uid := "enroll@example.com"
	enrollTOTP(t, handler, uid)

	data, err := dbUserMgr.GetTOTP(uid)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	if !data.Enabled {
		t.Error("TOTP should be enabled after confirm")
	}
}

func TestProfileTOTPDisable(t *testing.T) {
	handler := profileDemo()
	uid := "disable@example.com"
	cookies, _ := enrollTOTP(t, handler, uid)

	w := postProfileForm(handler, "/totp/disable", url.Values{}, cookies)
	if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
		t.Fatalf("disable: want 200 or 303, got %d", w.Code)
	}
	data, err := dbUserMgr.GetTOTP(uid)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	if data.Enabled {
		t.Error("TOTP should be disabled")
	}
}

