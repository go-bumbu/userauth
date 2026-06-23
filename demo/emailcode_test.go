package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var emailCodeRe = regexp.MustCompile(`email-code">(\d{6})<`)

func TestEmailCodeRequestUnknownEmail(t *testing.T) {
	handler := emailCodeDemo()
	form := url.Values{"email": {"nobody@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unknown email: want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Unknown email") {
		t.Errorf("want 'Unknown email' in body; got %s", w.Body.String())
	}
}

func TestEmailCodeRequestValidEmail(t *testing.T) {
	handler := emailCodeDemo()
	form := url.Values{"email": {"demo@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid email: want 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/emailcode/login/verify") {
		t.Errorf("want redirect to /emailcode/login/verify..., got %q", loc)
	}
}

func TestEmailCodeLoginHappyPath(t *testing.T) {
	handler := emailCodeDemo()

	// Step 1: request a code.
	form := url.Values{"email": {"demo@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("request code: want 303, got %d", w.Code)
	}

	// Step 2: GET the verify page and scrape the printed code.
	req = httptest.NewRequest(http.MethodGet, "/login/verify?email=demo@example.com", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	m := emailCodeRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("verify page missing login code; body=%s", w.Body.String())
	}
	code := m[1]

	// Step 3: submit the code.
	form = url.Values{"email": {"demo@example.com"}, "code": {code}}
	req = httptest.NewRequest(http.MethodPost, "/login/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("verify code: want 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/emailcode/protected" {
		t.Errorf("want redirect to /emailcode/protected, got %q", loc)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a session cookie after successful login")
	}

	// Step 4: access the protected page with the session cookie.
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("protected: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "demo@example.com") {
		t.Errorf("protected page should show the logged-in email; body=%s", w.Body.String())
	}
}

func TestEmailCodeLoginWrongCode(t *testing.T) {
	handler := emailCodeDemo()

	// Request a code so a pending entry exists.
	form := url.Values{"email": {"admin@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Submit a wrong code.
	form = url.Values{"email": {"admin@example.com"}, "code": {"000000"}}
	req = httptest.NewRequest(http.MethodPost, "/login/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("wrong code: want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid or expired") {
		t.Errorf("want error message; body=%s", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set on a wrong code")
	}
}
