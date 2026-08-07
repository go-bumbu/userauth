package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
)

func TestUserMgmtList(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())

	// page 1: first two login IDs (admin, admin@example.com), a Next link, no Prev
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page1: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "admin") {
		t.Error("page1: want 'admin' in body")
	}
	if !strings.Contains(body, "Next") {
		t.Error("page1: want a 'Next' link in body")
	}

	// page 2: the demo* login IDs and a Prev link
	req = httptest.NewRequest(http.MethodGet, "/?page=2", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page2: want 200, got %d", w.Code)
	}
	body = w.Body.String()
	if !strings.Contains(body, "demo") {
		t.Error("page2: want 'demo' in body")
	}
	if !strings.Contains(body, "Prev") {
		t.Error("page2: want a 'Prev' link in body")
	}
}

func TestUserMgmtCreate(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	form := url.Values{"login": {"uniquecreatetest"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/useradmin/" {
		t.Errorf("want redirect to /useradmin/, got %q", w.Header().Get("Location"))
	}
}

func TestUserMgmtCreateDuplicate(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
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
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	req := httptest.NewRequest(http.MethodPost, "/demo/disable", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("disable: want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/useradmin/" {
		t.Errorf("disable: want redirect to /useradmin/, got %q", w.Header().Get("Location"))
	}
}

func TestUserMgmtEnable(t *testing.T) {
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	handler := New(demotest.Logger(), users, demotest.Web())
	req := httptest.NewRequest(http.MethodPost, "/demo/enable", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("enable: want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/useradmin/" {
		t.Errorf("enable: want redirect to /useradmin/, got %q", w.Header().Get("Location"))
	}
}
