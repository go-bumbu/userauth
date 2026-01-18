package authenticator_test

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/go-bumbu/userauth/authenticator"
	"net/http"
	"net/http/httptest"
	"testing"
)

var _ = spew.Dump

// MockAuthHandler is a mock implementation of the AuthHandler interface.
type MockAuthHandler struct {
	name         string
	loggedIn     bool
	stopEval     bool
	handleAuthFn func(w http.ResponseWriter, r *http.Request) (bool, bool)
}

func (m *MockAuthHandler) Name() string {
	return m.name
}

func (m *MockAuthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) (bool, bool) {
	if m.handleAuthFn != nil {
		return m.handleAuthFn(w, r)
	}
	return m.loggedIn, m.stopEval
}

// TestEvalAuth verifies the behavior of EvalAuth.
func TestEvalAuth(t *testing.T) {
	tcs := []struct {
		name     string
		handlers []authenticator.AuthHandler
		expected bool
	}{
		{
			name: "Auth successful on first handler",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: true},
			},
			expected: true,
		},
		{
			name: "Auth successful after second handler",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: false},
				&MockAuthHandler{name: "handler2", loggedIn: true},
			},
			expected: true,
		},
		{
			name: "Auth stops evaluation",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", stopEval: true},
			},
			expected: false,
		},
		{
			name: "Auth fails for all handlers",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: false},
				&MockAuthHandler{name: "handler2", loggedIn: false},
			},
			expected: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator.New(tc.handlers, nil, nil, nil)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()

			result := auth.EvalAuth(rr, req)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestMiddleware ensures Middleware behaves as expected.
func TestMiddleware(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	tests := []struct {
		name           string
		handlers       []authenticator.AuthHandler
		unauthCallback func(w http.ResponseWriter, r *http.Request)
		expectedStatus int
	}{
		{
			name: "Authorized request",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: true},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Unauthorized request",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: false},
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Unauthorized request with callback",
			handlers: []authenticator.AuthHandler{
				&MockAuthHandler{name: "handler1", loggedIn: false},
			},
			unauthCallback: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Forbidden"))
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth := authenticator.New(tc.handlers, nil, tc.unauthCallback, nil)

			middleware := auth.Middleware(mockHandler)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()

			middleware.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}
