package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUserMgmtList(t *testing.T) {
	handler := userMgmtDemo()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "admin") {
		t.Error("want 'admin' in response body")
	}
	if !strings.Contains(body, "demo") {
		t.Error("want 'demo' in response body")
	}
}

func TestUserMgmtCreate(t *testing.T) {
	handler := userMgmtDemo()
	form := url.Values{"login": {"uniquecreatetest"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/users/" {
		t.Errorf("want redirect to /users/, got %q", w.Header().Get("Location"))
	}
}

func TestUserMgmtCreateDuplicate(t *testing.T) {
	handler := userMgmtDemo()
	form := url.Values{"login": {"admin"}, "password": {"admin"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Error:") {
		t.Error("want 'Error:' in response body")
	}
}

func TestUserMgmtDisable(t *testing.T) {
	handler := userMgmtDemo()
	req := httptest.NewRequest(http.MethodPost, "/demo/disable", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("disable: want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/users/" {
		t.Errorf("disable: want redirect to /users/, got %q", w.Header().Get("Location"))
	}
}

func TestUserMgmtEnable(t *testing.T) {
	handler := userMgmtDemo()
	req := httptest.NewRequest(http.MethodPost, "/demo/enable", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("enable: want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/users/" {
		t.Errorf("enable: want redirect to /users/, got %q", w.Header().Get("Location"))
	}
}
