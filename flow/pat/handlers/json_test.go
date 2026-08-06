package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/pat/handlers"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
)

type fakeUsers struct{}

func (fakeUsers) GetUser(id string) (userauth.User, error) {
	if id == "u1" || id == "u2" {
		return userauth.User{ID: id, LoginID: id + "@example.com", Enabled: true}, nil
	}
	return userauth.User{}, userauth.ErrUserNotFound
}
func (fakeUsers) GetUserByLogin(loginID string) (userauth.User, error) {
	return userauth.User{}, userauth.ErrUserNotFound
}

// newFixture returns handlers whose UserID func returns the value of the
// X-Test-User header, or an error when absent (simulating no session).
func newFixture(t *testing.T) (*handlers.JSON, *patsvc.Service) {
	t.Helper()
	svc, err := patsvc.NewService(memory.New(), fakeUsers{}, patsvc.Opts{MaxPerUser: 3})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h := handlers.New(handlers.Cfg{
		Service: svc,
		UserID: func(r *http.Request) (string, error) {
			u := r.Header.Get("X-Test-User")
			if u == "" {
				return "", fmt.Errorf("no session")
			}
			return u, nil
		},
	})
	return h, svc
}

func doJSON(t *testing.T, h http.Handler, method, path, user string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestCreateReturnsTokenOnce(t *testing.T) {
	h, _ := newFixture(t)
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	w := doJSON(t, h.CreateHandler(), http.MethodPost, "/", "u1",
		map[string]any{"name": "ci", "scopes": []string{"read"}, "expires_at": exp})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token   string `json:"token"`
		TokenID string `json:"token_id"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Token, "pat_") || resp.TokenID == "" || resp.Name != "ci" {
		t.Errorf("create response mismatch: %+v", resp)
	}

	// list must never repeat the token or any hash
	lw := doJSON(t, h.ListHandler(), http.MethodGet, "/", "u1", nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("list status = %d", lw.Code)
	}
	body := lw.Body.String()
	if strings.Contains(body, resp.Token) {
		t.Error("list response contains the plaintext token")
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "hash") {
		t.Errorf("list response leaks secret material: %s", body)
	}
	if !strings.Contains(body, resp.TokenID) {
		t.Error("list response missing the created token's metadata")
	}
}

func TestCreateValidationErrors(t *testing.T) {
	h, _ := newFixture(t)
	tests := []struct {
		name string
		body any
		want int
	}{
		{"empty name", map[string]any{"name": ""}, http.StatusBadRequest},
		{"past expiry", map[string]any{"name": "x", "expires_at": time.Now().Add(-time.Hour)}, http.StatusBadRequest},
		{"malformed json", "not json", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, h.CreateHandler(), http.MethodPost, "/", "u1", tc.body)
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestCreateTooManyTokens(t *testing.T) {
	h, _ := newFixture(t)
	for i := 0; i < 3; i++ {
		w := doJSON(t, h.CreateHandler(), http.MethodPost, "/", "u1", map[string]any{"name": "t"})
		if w.Code != http.StatusCreated {
			t.Fatalf("create %d: %d", i, w.Code)
		}
	}
	w := doJSON(t, h.CreateHandler(), http.MethodPost, "/", "u1", map[string]any{"name": "t"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("over-limit create: status = %d, want 400", w.Code)
	}
}

func TestDelete(t *testing.T) {
	h, svc := newFixture(t)
	_, rec, err := svc.Mint("u1", "mine", nil, nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// foreign token → 404
	w := doJSON(t, h.DeleteHandler(), http.MethodDelete, "/"+rec.TokenID, "u2", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("foreign delete: status = %d, want 404", w.Code)
	}
	// owner → 204
	w = doJSON(t, h.DeleteHandler(), http.MethodDelete, "/"+rec.TokenID, "u1", nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("owner delete: status = %d, want 204", w.Code)
	}
	// again → 404
	w = doJSON(t, h.DeleteHandler(), http.MethodDelete, "/"+rec.TokenID, "u1", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("repeat delete: status = %d, want 404", w.Code)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	h, _ := newFixture(t)
	for name, do := range map[string]func() *httptest.ResponseRecorder{
		"create": func() *httptest.ResponseRecorder {
			return doJSON(t, h.CreateHandler(), http.MethodPost, "/", "", map[string]any{"name": "x"})
		},
		"list": func() *httptest.ResponseRecorder {
			return doJSON(t, h.ListHandler(), http.MethodGet, "/", "", nil)
		},
		"delete": func() *httptest.ResponseRecorder {
			return doJSON(t, h.DeleteHandler(), http.MethodDelete, "/abc", "", nil)
		},
	} {
		if w := do(); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without session: status = %d, want 401", name, w.Code)
		}
	}
}

func TestDeleteBadTokenID(t *testing.T) {
	h, _ := newFixture(t)
	for _, path := range []string{"/", "/."} {
		w := doJSON(t, h.DeleteHandler(), http.MethodDelete, path, "u1", nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("delete %q: status = %d, want 400", path, w.Code)
		}
	}
}

func TestPresetDefaultUserID(t *testing.T) {
	// Test that New() uses the default cookieSessionUserID when UserID is nil
	svc, err := patsvc.NewService(memory.New(), fakeUsers{}, patsvc.Opts{MaxPerUser: 3})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h := handlers.New(handlers.Cfg{Service: svc})
	if h.Flow == nil || h.Flow.UserID == nil {
		t.Error("New with nil UserID should use default")
	}
}

func TestMethodEnforcement(t *testing.T) {
	h, _ := newFixture(t)
	tests := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		want    int
	}{
		{"CreateHandler rejects GET", h.CreateHandler(), http.MethodGet, "/", http.StatusMethodNotAllowed},
		{"CreateHandler rejects PUT", h.CreateHandler(), http.MethodPut, "/", http.StatusMethodNotAllowed},
		{"CreateHandler accepts POST", h.CreateHandler(), http.MethodPost, "/", http.StatusBadRequest}, // 400 for bad body, not 405
		{"ListHandler rejects POST", h.ListHandler(), http.MethodPost, "/", http.StatusMethodNotAllowed},
		{"ListHandler rejects DELETE", h.ListHandler(), http.MethodDelete, "/", http.StatusMethodNotAllowed},
		{"ListHandler accepts GET", h.ListHandler(), http.MethodGet, "/", http.StatusOK},
		{"DeleteHandler rejects GET", h.DeleteHandler(), http.MethodGet, "/abc", http.StatusMethodNotAllowed},
		{"DeleteHandler rejects POST", h.DeleteHandler(), http.MethodPost, "/abc", http.StatusMethodNotAllowed},
		{"DeleteHandler accepts DELETE", h.DeleteHandler(), http.MethodDelete, "/abc", http.StatusNotFound}, // 404 for token not found, not 405
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, tc.handler, tc.method, tc.path, "u1", nil)
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
