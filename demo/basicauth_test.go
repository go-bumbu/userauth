package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	initLogger()
	os.Exit(m.Run())
}

func TestBasicAuthEnforce(t *testing.T) {
	handler := basicAuthDemo()

	t.Run("no credentials returns 401 with WWW-Authenticate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/enforce", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Error("want WWW-Authenticate header, got none")
		}
	})

	t.Run("valid credentials returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/enforce", nil)
		req.SetBasicAuth("admin", "admin")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("want 200, got %d", w.Code)
		}
	})

	t.Run("wrong password returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/enforce", nil)
		req.SetBasicAuth("admin", "wrong")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", w.Code)
		}
	})
}

func TestBasicAuthSilent(t *testing.T) {
	handler := basicAuthDemo()

	t.Run("no credentials returns 401 without WWW-Authenticate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/silent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") != "" {
			t.Error("want no WWW-Authenticate header in silent mode")
		}
	})

	t.Run("valid credentials returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/silent", nil)
		req.SetBasicAuth("demo", "demo")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("want 200, got %d", w.Code)
		}
	})
}
