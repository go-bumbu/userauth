package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

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
