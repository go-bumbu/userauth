package profile

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/pquerna/otp/totp"
)

// newProfileHandler builds the profile handler with the second-factor services
// over a fresh seeded store, exactly as demo/main.go wires them.
func newProfileHandler(t *testing.T) (http.Handler, *userdb.Store, mfa.Services) {
	t.Helper()
	stores, err := demotest.NewStores()
	if err != nil {
		t.Fatal(err)
	}
	mfaSvc, err := mfa.New(demotest.Logger(), stores)
	if err != nil {
		t.Fatal(err)
	}
	return New(demotest.Logger(), stores, mfaSvc, demotest.Web()), stores.Users, mfaSvc
}

var totpSecretRe = regexp.MustCompile(`totp-secret">([A-Z2-7]+)<`)

// canonicalID resolves the login ID to the canonical user ID that the services
// key on.
func canonicalID(t *testing.T, users *userdb.Store, loginID string) string {
	t.Helper()
	usr, err := users.GetUserByLogin(loginID)
	if err != nil {
		t.Fatalf("get user %q: %v", loginID, err)
	}
	return usr.ID
}

// enableTOTP enrols a user through the service and returns the secret, the way
// the profile UI does: the service generates the secret, so tests never write
// one into the store themselves.
func enableTOTP(t *testing.T, mfaSvc mfa.Services, users *userdb.Store, loginID string) string {
	t.Helper()
	userID := canonicalID(t, users, loginID)
	enrolment, err := mfaSvc.TOTP.Enroll(userID, loginID)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ok, err := mfaSvc.TOTP.Confirm(userID, code)
	if err != nil || !ok {
		t.Fatalf("confirm enrolment: (%v, %v)", ok, err)
	}
	return enrolment.Secret
}

// enrollTOTP logs in a fresh user (one-step), runs setup+confirm, and returns the
// login cookies and the confirm-response recorder. Fails the test on any error.
func enrollTOTP(t *testing.T, handler http.Handler, users *userdb.Store, uid string) ([]*http.Cookie, string) {
	t.Helper()
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after one-step login")
	}
	sw := demotest.PostForm(handler, "/totp/setup", url.Values{}, cookies)
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
	cw := demotest.PostForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	if cw.Code != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d", cw.Code)
	}
	return cookies, secret
}

func TestProfileTOTPEnroll(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "enroll@example.com"
	enrollTOTP(t, handler, users, uid)

	enabled, err := mfaSvc.TOTP.Enabled(canonicalID(t, users, uid))
	if err != nil {
		t.Fatalf("totp enabled: %v", err)
	}
	if !enabled {
		t.Error("TOTP should be enabled after confirm")
	}
}

func TestProfileTOTPDisable(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "disable@example.com"
	cookies, _ := enrollTOTP(t, handler, users, uid)

	w := demotest.PostForm(handler, "/totp/disable", url.Values{}, cookies)
	if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
		t.Fatalf("disable: want 200 or 303, got %d", w.Code)
	}
	enabled, err := mfaSvc.TOTP.Enabled(canonicalID(t, users, uid))
	if err != nil {
		t.Fatalf("totp enabled: %v", err)
	}
	if enabled {
		t.Error("TOTP should be disabled")
	}
}

var recoveryCodeRe = regexp.MustCompile(`recovery-code">([^<]+)<`)

func TestProfileTOTPRecoveryCodesShown(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "reccodes@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := demotest.PostForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := demotest.PostForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)

	matches := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)
	if len(matches) != 6 {
		t.Fatalf("want 6 recovery codes shown, got %d; body=%s", len(matches), cw.Body.String())
	}
	count, err := mfaSvc.Recovery.Remaining(canonicalID(t, users, uid))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 6 {
		t.Errorf("want 6 stored recovery codes, got %d", count)
	}
}

func TestProfileRecoveryCodeLogin(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "reclogin@example.com"
	if err := users.Create(uid, "pw"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	lw := demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	cookies := lw.Result().Cookies()
	sw := demotest.PostForm(handler, "/totp/setup", url.Values{}, cookies)
	secret := totpSecretRe.FindStringSubmatch(sw.Body.String())[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	cw := demotest.PostForm(handler, "/totp/confirm", url.Values{"code": {code}}, cookies)
	recCode := recoveryCodeRe.FindAllStringSubmatch(cw.Body.String(), -1)[0][1]

	// password step establishes the pending login
	_ = demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	// log in with the recovery code
	w := demotest.PostForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("recovery login: want 303, got %d", w.Code)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie after recovery-code login")
	}
	count, _ := mfaSvc.Recovery.Remaining(canonicalID(t, users, uid))
	if count != 5 {
		t.Errorf("want 5 remaining recovery codes after use, got %d", count)
	}

	// reusing the same code must fail
	_ = demotest.PostForm(handler, "/login", url.Values{"username": {uid}, "password": {"pw"}}, nil)
	w = demotest.PostForm(handler, "/login/2fa", url.Values{"userID": {uid}, "code": {recCode}}, nil)
	if len(w.Result().Cookies()) != 0 {
		t.Error("reused recovery code must not authenticate")
	}
}

func TestProfileTOTPDisableClearsRecoveryCodes(t *testing.T) {
	handler, users, mfaSvc := newProfileHandler(t)
	uid := "discodes@example.com"
	cookies, _ := enrollTOTP(t, handler, users, uid)
	_ = demotest.PostForm(handler, "/totp/disable", url.Values{}, cookies)

	count, err := mfaSvc.Recovery.Remaining(canonicalID(t, users, uid))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("want 0 recovery codes after disable, got %d", count)
	}
}
