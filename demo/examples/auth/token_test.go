package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenMintAndAccessWithBearer(t *testing.T) {
	handler := Token(testLogger(), staticDemoUsers(), testWeb())

	// mint a token
	req := httptest.NewRequest(http.MethodGet, "/new", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("mint token: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "token: pat_") {
		t.Fatalf("mint response should contain token, got: %s", body)
	}
	// extract the token (it's the first line after "token: ")
	lines := strings.Split(body, "\n")
	var token string
	for _, line := range lines {
		if strings.HasPrefix(line, "token: ") {
			token = strings.TrimPrefix(line, "token: ")
			break
		}
	}
	if token == "" {
		t.Fatalf("could not extract token from response: %s", body)
	}

	// access /protected with Bearer
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Bearer access: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "demo") {
		t.Errorf("Bearer access: body should name the user, got: %s", w.Body.String())
	}
}

func TestTokenAccessWithCustomHeader(t *testing.T) {
	handler := Token(testLogger(), staticDemoUsers(), testWeb())

	// mint a token
	req := httptest.NewRequest(http.MethodGet, "/new", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("mint token: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	lines := strings.Split(body, "\n")
	var token string
	for _, line := range lines {
		if strings.HasPrefix(line, "token: ") {
			token = strings.TrimPrefix(line, "token: ")
			break
		}
	}

	// access /protected with X-Api-Token
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Api-Token", token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("X-Api-Token access: want 200, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestTokenNoCredentialsReturns401(t *testing.T) {
	handler := Token(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no credentials: want 401, got %d", w.Code)
	}
}

func TestTokenInvalidTokenReturns401(t *testing.T) {
	handler := Token(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer pat_invalid")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("invalid token: want 401, got %d", w.Code)
	}
}

func TestTokenBasicAuthLinkWorks(t *testing.T) {
	handler := Token(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.SetBasicAuth("demo", "demo")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("basic auth link: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "authenticated") {
		t.Errorf("basic auth: body should confirm authentication, got: %s", w.Body.String())
	}
}
