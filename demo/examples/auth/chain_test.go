package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChainUnauthenticatedRedirectsToLogin(t *testing.T) {
	handler := Chain(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303 redirect from the unauthorized callback, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/chain/login" {
		t.Errorf("want redirect to /chain/login, got %q", loc)
	}
}

func TestChainBasicAuthLink(t *testing.T) {
	handler := Chain(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.SetBasicAuth("demo", "demo")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("basic auth link: want 200, got %d", w.Code)
	}
}

func TestChainCookieLink(t *testing.T) {
	handler := Chain(testLogger(), staticDemoUsers(), testWeb())

	// log in to obtain a session cookie
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: want 303, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a session cookie")
	}

	// the cookie link of the chain authenticates the request, no basic auth needed
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cookie link: want 200, got %d", w.Code)
	}
}

func TestChainWrongBasicAuthRedirects(t *testing.T) {
	handler := Chain(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.SetBasicAuth("demo", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("wrong credentials: want 303 to login, got %d", w.Code)
	}
}
