package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPLoginWrongPassword(t *testing.T) {
	handler := TOTP(testLogger(), testWeb())
	w := postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"wrong"}})
	if w.Code != http.StatusOK {
		t.Fatalf("wrong password: want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid credentials") {
		t.Errorf("want error message; body=%s", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a wrong password")
	}
}

func TestTOTPLoginHappyPath(t *testing.T) {
	handler := TOTP(testLogger(), testWeb())

	// Step 1: password.
	w := postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("password step: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/totp/login/verify") {
		t.Errorf("want redirect to /totp/login/verify..., got %q", loc)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set at the password step")
	}

	// Step 2: authenticator code.
	code, err := totp.GenerateCode(demoTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w = postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("totp step: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/totp/protected" {
		t.Errorf("want redirect to /totp/protected, got %q", loc)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a session cookie after the TOTP step")
	}

	// Step 3: access the protected page with the session cookie.
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected: want 200, got %d", rec.Code)
	}
}

// TestTOTPLoginCodeWithoutPassword asserts the flow's ordering invariant: the
// TOTP factor is rejected while the policy is still waiting for the password,
// even when the submitted code itself is valid.
func TestTOTPLoginCodeWithoutPassword(t *testing.T) {
	handler := TOTP(testLogger(), testWeb())
	code, err := totp.GenerateCode(demoTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w := postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusOK {
		t.Fatalf("totp without password: want 200 (error page), got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set when the password step was skipped")
	}
}

func TestTOTPLoginWrongCode(t *testing.T) {
	handler := TOTP(testLogger(), testWeb())
	_ = postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})

	w := postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {"000000"}})
	if w.Code != http.StatusOK {
		t.Fatalf("wrong code: want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid code") {
		t.Errorf("want error message; body=%s", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a wrong code")
	}
}

// postForm posts a urlencoded form to handler without cookies.
func postForm(handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}
