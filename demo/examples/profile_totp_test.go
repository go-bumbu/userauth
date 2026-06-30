package examples

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/userstore/dbuser"
	"github.com/pquerna/otp/totp"
)

var totpSecretRe = regexp.MustCompile(`totp-secret">([A-Z2-7]+)<`)

// enrollTOTP logs in a fresh user (one-step), runs setup+confirm, and returns the
// login cookies and the confirm-response recorder. Fails the test on any error.
func enrollTOTP(t *testing.T, handler http.Handler, users *dbuser.Store, uid string) ([]*http.Cookie, string) {
	t.Helper()
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after one-step login")
	}
	sw := postForm(handler, "/totp/setup", url.Values{}, cookies)
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
	cw := postForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	if cw.Code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", cw.Code)
	}
	return cookies, secret
}

func TestProfileTOTPEnroll(t *testing.T) {
	users, err := SeededStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := Profile(testLogger(), users, testWeb())
	uid := "enroll@example.com"
	enrollTOTP(t, handler, users, uid)

	data, err := users.GetTOTP(uid)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	if !data.Enabled {
		t.Error("TOTP should be enabled after confirm")
	}
}

func TestProfileTOTPDisable(t *testing.T) {
	users, err := SeededStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := Profile(testLogger(), users, testWeb())
	uid := "disable@example.com"
	cookies, _ := enrollTOTP(t, handler, users, uid)

	w := postForm(handler, "/totp/disable", url.Values{}, cookies)
	if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
		t.Fatalf("disable: want 200 or 303, got %d", w.Code)
	}
	data, err := users.GetTOTP(uid)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	if data.Enabled {
		t.Error("TOTP should be disabled")
	}
}

var recoveryCodeRe = regexp.MustCompile(`recovery-code">([^<]+)<`)

func TestProfileTOTPRecoveryCodesShown(t *testing.T) {
	users, err := SeededStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := Profile(testLogger(), users, testWeb())
	uid := "reccodes@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := postForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := postForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)

	matches := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)
	if len(matches) != 6 {
		t.Fatalf("want 6 recovery codes shown, got %d; body=%s", len(matches), cw.Body.String())
	}
	count, err := users.GetRecoveryCodesCount(uid)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 6 {
		t.Errorf("want 6 stored recovery codes, got %d", count)
	}
}

func TestProfileRecoveryCodeLogin(t *testing.T) {
	users, err := SeededStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := Profile(testLogger(), users, testWeb())
	uid := "reclogin@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := postForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := postForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := postForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	recCode := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)[0][1]

	// password step establishes the pending login
	_ = postForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	// log in with the recovery code
	w := postForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("recovery login: want 303, got %d", w.Code)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie after recovery-code login")
	}
	count, _ := users.GetRecoveryCodesCount(uid)
	if count != 5 {
		t.Errorf("want 5 remaining recovery codes after use, got %d", count)
	}

	// reusing the same code must fail
	_ = postForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	w = postForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Error("reused recovery code must not authenticate")
	}
}

func TestProfileTOTPDisableClearsRecoveryCodes(t *testing.T) {
	users, err := SeededStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := Profile(testLogger(), users, testWeb())
	uid := "discodes@example.com"
	cookies, _ := enrollTOTP(t, handler, users, uid)
	_ = postForm(handler, "/totp/disable", url.Values{}, cookies)

	count, err := users.GetRecoveryCodesCount(uid)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("want 0 recovery codes after disable, got %d", count)
	}
}
