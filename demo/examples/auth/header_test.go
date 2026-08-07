package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getWithHeader(t *testing.T, handler http.Handler, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if user != "" {
		req.Header.Set("X-User-Auth", user)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestHeaderAuth(t *testing.T) {
	handler := Header(testLogger(), testWeb())

	t.Run("no header returns 401", func(t *testing.T) {
		w := getWithHeader(t, handler, "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", w.Code)
		}
	})

	t.Run("proxy-asserted identity returns 200", func(t *testing.T) {
		w := getWithHeader(t, handler, "admin")
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "authenticated as: admin") {
			t.Errorf("want authenticated-as text; body=%s", w.Body.String())
		}
	})
}
