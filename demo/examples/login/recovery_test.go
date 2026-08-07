package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var recoveryCodeRe = regexp.MustCompile(`email-code"[^>]*>([a-z0-9]{8})<`)

func TestRecoveryLoginHappyPath(t *testing.T) {
	handler := Recovery(testLogger(), testWeb())

	// Step 1: password.
	w := postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("password step: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/recovery/login/verify") {
		t.Errorf("want redirect to /recovery/login/verify..., got %q", loc)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set at the password step")
	}

	// Step 2: GET the verify page and scrape a remaining recovery code.
	req := httptest.NewRequest(http.MethodGet, "/login/verify?user=demo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	m := recoveryCodeRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("verify page missing recovery codes; body=%s", rec.Body.String())
	}
	code := m[1]

	// Step 3: submit the recovery code.
	w = postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("recovery step: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/recovery/protected" {
		t.Errorf("want redirect to /recovery/protected, got %q", loc)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a session cookie after the recovery step")
	}

	// Step 4: access the protected page with the session cookie.
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected: want 200, got %d", rec.Code)
	}
}

// TestRecoveryLoginCodeIsSingleUse asserts that a consumed recovery code
// cannot complete a second login.
func TestRecoveryLoginCodeIsSingleUse(t *testing.T) {
	handler := Recovery(testLogger(), testWeb())

	// First login consumes the code.
	_ = postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})
	req := httptest.NewRequest(http.MethodGet, "/login/verify?user=demo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	m := recoveryCodeRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("verify page missing recovery codes; body=%s", rec.Body.String())
	}
	code := m[1]
	w := postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first use: want 303, got %d", w.Code)
	}

	// Second login replays the same code; it must be rejected.
	_ = postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})
	w = postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusOK {
		t.Fatalf("replayed code: want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid or already used") {
		t.Errorf("want error message; body=%s", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a replayed code")
	}
}

// TestRecoveryLoginCodeWithoutPassword asserts the flow's ordering invariant:
// a valid recovery code is rejected while the policy still waits for the
// password, and the code is not consumed by the rejected submission.
func TestRecoveryLoginCodeWithoutPassword(t *testing.T) {
	handler := Recovery(testLogger(), testWeb())

	req := httptest.NewRequest(http.MethodGet, "/login/verify?user=demo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	m := recoveryCodeRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("verify page missing recovery codes; body=%s", rec.Body.String())
	}
	code := m[1]

	w := postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusOK {
		t.Fatalf("recovery without password: want 200 (error page), got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set when the password step was skipped")
	}

	// The rejected submission must not have burned the code.
	_ = postForm(handler, "/login", url.Values{"username": {"demo"}, "password": {"demo"}})
	w = postForm(handler, "/login/verify", url.Values{"username": {"demo"}, "code": {code}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code should still be usable after a rejected early submission: want 303, got %d", w.Code)
	}
}
