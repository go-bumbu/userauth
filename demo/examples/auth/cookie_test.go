package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCookieAuth(t *testing.T) {
	handler := Cookie(testLogger(), testWeb())

	t.Run("no cookie returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", w.Code)
		}
	})

	t.Run("session cookie authenticates the request", func(t *testing.T) {
		// start a session
		req := httptest.NewRequest(http.MethodGet, "/start", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("start: want 303, got %d", w.Code)
		}
		cookies := w.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected a session cookie")
		}

		// access the protected page with the cookie
		req = httptest.NewRequest(http.MethodGet, "/protected", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("protected: want 200, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "authenticated as: demo") {
			t.Errorf("want authenticated-as text; body=%s", w.Body.String())
		}

		// end the session and verify the cookie no longer grants access
		req = httptest.NewRequest(http.MethodGet, "/end", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("end: want 303, got %d", w.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/protected", nil)
		for _, c := range w.Result().Cookies() {
			req.AddCookie(c)
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("after logout: want 401, got %d", w.Code)
		}
	})
}
