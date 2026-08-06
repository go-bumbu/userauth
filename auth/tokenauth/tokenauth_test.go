package tokenauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bumbu/userauth/auth/tokenauth"
)

// fakeVerifier accepts exactly one token value.
type fakeVerifier struct {
	valid string
	data  tokenauth.RequestData
	err   error
}

func (f fakeVerifier) Verify(token string) (tokenauth.RequestData, bool, error) {
	if f.err != nil {
		return tokenauth.RequestData{}, false, f.err
	}
	if token == f.valid {
		return f.data, true, nil
	}
	return tokenauth.RequestData{}, false, nil
}

func newHandler(t *testing.T, cfg tokenauth.Cfg) *tokenauth.Handler {
	t.Helper()
	h, err := tokenauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestNewRequiresVerifier(t *testing.T) {
	if _, err := tokenauth.New(tokenauth.Cfg{}); err == nil {
		t.Error("New without Verifier should error")
	}
}

func TestHandleAuthTruthTable(t *testing.T) {
	good := fakeVerifier{valid: "pat_AAAAAAAA_secret", data: tokenauth.RequestData{UserID: "u1", Scopes: []string{"read"}}}
	validToken := "pat_AAAAAAAA_secret"
	whitespaceToken := "  " + validToken + "  "
	tests := []struct {
		name       string
		cfg        tokenauth.Cfg
		authHeader string
		custom     map[string]string
		wantAllow  bool
		wantStop   bool
	}{
		{"no token falls through", tokenauth.Cfg{Verifier: good}, "", nil, false, false},
		{"no token falls through even when enforcing", tokenauth.Cfg{Verifier: good, Enforce: true}, "", nil, false, false},
		{"valid bearer token", tokenauth.Cfg{Verifier: good}, "Bearer " + validToken, nil, true, false},
		{"bearer scheme is case-insensitive", tokenauth.Cfg{Verifier: good}, "bearer " + validToken, nil, true, false},
		{"invalid token no enforce", tokenauth.Cfg{Verifier: good}, "Bearer wrong", nil, false, false},
		{"invalid token with enforce stops", tokenauth.Cfg{Verifier: good, Enforce: true}, "Bearer wrong", nil, false, true},
		{"basic auth header falls through untouched", tokenauth.Cfg{Verifier: good, Enforce: true}, "Basic dXNlcjpwdw==", nil, false, false},
		{"custom header accepted", tokenauth.Cfg{Verifier: good, CustomHeader: "X-Api-Token"},
			"", map[string]string{"X-Api-Token": validToken}, true, false},
		{"custom header trims whitespace", tokenauth.Cfg{Verifier: good, CustomHeader: "X-Api-Token"},
			"", map[string]string{"X-Api-Token": whitespaceToken}, true, false},
		{"authorization beats custom header", tokenauth.Cfg{Verifier: good, CustomHeader: "X-Api-Token"},
			"Bearer wrong", map[string]string{"X-Api-Token": validToken}, false, false},
		{"custom scheme", tokenauth.Cfg{Verifier: good, BearerScheme: "Token"},
			"Token " + validToken, nil, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t, tc.cfg)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authHeader != "" {
				r.Header.Set("Authorization", tc.authHeader)
			}
			for k, v := range tc.custom {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			allow, stop := h.HandleAuth(w, r)
			if allow != tc.wantAllow || stop != tc.wantStop {
				t.Errorf("HandleAuth = (%v, %v), want (%v, %v)", allow, stop, tc.wantAllow, tc.wantStop)
			}
			if tc.wantAllow {
				data, err := tokenauth.CtxGetRequestData(r)
				if err != nil {
					t.Fatalf("CtxGetRequestData: %v", err)
				}
				if data.UserID != "u1" || len(data.Scopes) != 1 {
					t.Errorf("context data mismatch: %+v", data)
				}
			}
		})
	}
}

func TestHandleAuthVerifierError(t *testing.T) {
	h := newHandler(t, tokenauth.Cfg{Verifier: fakeVerifier{err: errors.New("db down")}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	allow, stop := h.HandleAuth(w, r)
	if allow || !stop {
		t.Errorf("I/O error: HandleAuth = (%v, %v), want (false, true)", allow, stop)
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("I/O error must write 500, got %d", w.Code)
	}
}

func TestMiddleware(t *testing.T) {
	good := fakeVerifier{valid: "tok", data: tokenauth.RequestData{UserID: "u1"}}
	h := newHandler(t, tokenauth.Cfg{Verifier: good})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	mw := h.Middleware(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Errorf("valid token should reach next handler, got %d", w.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token should 401, got %d", w.Code)
	}
}

func TestCtxGetRequestDataWithoutAuth(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := tokenauth.CtxGetRequestData(r); err == nil {
		t.Error("empty context should error")
	}
}
