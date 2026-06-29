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

var recoveryCodeRe = regexp.MustCompile(`recovery-code">([^<]+)<`)

func TestProfileTOTPRecoveryCodesShown(t *testing.T) {
	handler := profileDemo()
	uid := "reccodes@example.com"
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := postProfileForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := postProfileForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)

	matches := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)
	if len(matches) != 6 {
		t.Fatalf("want 6 recovery codes shown, got %d; body=%s", len(matches), cw.Body.String())
	}
	count, err := dbUserMgr.GetRecoveryCodesCount(uid)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 6 {
		t.Errorf("want 6 stored recovery codes, got %d", count)
	}
}

func TestProfileRecoveryCodeLogin(t *testing.T) {
	handler := profileDemo()
	uid := "reclogin@example.com"
	if err := dbUserMgr.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := postProfileForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := postProfileForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	recCode := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)[0][1]

	// password step establishes the pending login
	_ = postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	// log in with the recovery code
	w := postProfileForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("recovery login: want 303, got %d", w.Code)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie after recovery-code login")
	}
	count, _ := dbUserMgr.GetRecoveryCodesCount(uid)
	if count != 5 {
		t.Errorf("want 5 remaining recovery codes after use, got %d", count)
	}

	// reusing the same code must fail
	_ = postProfileForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	w = postProfileForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Error("reused recovery code must not authenticate")
	}
}

func TestProfileTOTPDisableClearsRecoveryCodes(t *testing.T) {
	handler := profileDemo()
	uid := "discodes@example.com"
	cookies, _ := enrollTOTP(t, handler, uid)
	_ = postProfileForm(handler, "/totp/disable", url.Values{}, cookies)

	count, err := dbUserMgr.GetRecoveryCodesCount(uid)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("want 0 recovery codes after disable, got %d", count)
	}
}

