package profile

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
)

// loginUser posts the login form and returns session cookies.
func loginUser(handler http.Handler, username, password string) []*http.Cookie {
	w := demotest.PostForm(handler, "/login", url.Values{"username": {username}, "password": {password}}, nil)
	return w.Result().Cookies()
}

func TestProfilePATCreate(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	cookies := loginUser(handler, "demo@example.com", "demo")

	w := demotest.PostForm(handler, "/pat/create", url.Values{"name": {"test"}, "expiry_days": {"30"}}, cookies)
	if w.Code != http.StatusOK {
		t.Fatalf("create: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pat_") {
		t.Fatalf("expected pat_ token in body; got: %s", body)
	}
	if !strings.Contains(body, "Token created") {
		t.Errorf("expected 'Token created' message in body")
	}
}

func TestProfilePATList(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	cookies := loginUser(handler, "demo@example.com", "demo")

	// Create a token
	w := demotest.PostForm(handler, "/pat/create", url.Values{"name": {"test"}}, cookies)
	if w.Code != http.StatusOK {
		t.Fatalf("create: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pat_") {
		t.Fatalf("expected token in create response")
	}

	// GET the PAT page
	req := httptest.NewRequest(http.MethodGet, "/pat", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)

	if w2.Code != http.StatusOK {
		t.Fatalf("GET /pat: want 200, got %d", w2.Code)
	}
	listBody := w2.Body.String()
	if !strings.Contains(listBody, "test") {
		t.Errorf("list should contain token name 'test', got: %s", listBody)
	}
}

func TestProfilePATRevoke(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	cookies := loginUser(handler, "demo@example.com", "demo")

	// Create a token
	w := demotest.PostForm(handler, "/pat/create", url.Values{"name": {"test"}}, cookies)
	body := w.Body.String()

	// Extract token_id from the page (it's in a hidden input or table cell)
	// The template shows it in <code>{{.TokenID}}</code> in the table
	tokenIDRe := regexp.MustCompile(`<code[^>]*>([^<]+)</code>`)
	matches := tokenIDRe.FindAllStringSubmatch(body, -1)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 code blocks (plaintext + tokenID), got %d", len(matches))
	}
	// First is the plaintext token, second should be the tokenID in the table
	tokenID := matches[1][1]
	if strings.HasPrefix(tokenID, "pat_") {
		t.Errorf("tokenID should be the short ID, not the full token; got %q", tokenID)
	}

	// Revoke the token
	w2 := demotest.PostForm(handler, "/pat/revoke", url.Values{"token_id": {tokenID}}, cookies)
	if w2.Code != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "Token revoked") {
		t.Errorf("expected 'Token revoked' message in body")
	}

	// GET the PAT page again — the token should be gone
	req := httptest.NewRequest(http.MethodGet, "/pat", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req)
	if strings.Contains(w3.Body.String(), "test") {
		t.Errorf("token 'test' should no longer appear after revoke")
	}
}

func TestProfilePATRedirectIfNotAuthenticated(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())

	// GET /pat without cookies
	req := httptest.NewRequest(http.MethodGet, "/pat", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/profile/login" {
		t.Errorf("want redirect to /profile/login, got %q", loc)
	}
}
