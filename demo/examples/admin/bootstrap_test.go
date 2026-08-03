package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
)

// getStatus fetches /status and returns the needsSetup flag.
func getStatus(t *testing.T, handler http.Handler) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var got map[string]bool
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got["needsSetup"]
}

func TestBootstrapScenario(t *testing.T) {
	handler := NewBootstrap(demotest.Logger(), demotest.Web())

	// startup bootstrap already seeded the admin
	if getStatus(t, handler) {
		t.Error("after startup: want needsSetup=false")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "admin") {
		t.Error("want seeded 'admin' in user list")
	}

	// create a second admin
	w = demotest.PostForm(handler, "/", url.Values{"login": {"admin2"}, "password": {"pw"}}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Created user admin2") {
		t.Fatalf("create admin2: code=%d body=%q", w.Code, w.Body.String())
	}

	// delete the original admin
	w = demotest.PostForm(handler, "/admin/delete", url.Values{}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Deleted user admin") {
		t.Fatalf("delete admin: code=%d body=%q", w.Code, w.Body.String())
	}

	// re-running bootstrap must be a no-op: admin2 still exists
	w = demotest.PostForm(handler, "/run", url.Values{}, nil)
	if !strings.Contains(w.Body.String(), "no-op") {
		t.Errorf("bootstrap on populated store: want no-op message, got %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `<td>admin</td>`) {
		t.Error("deleted admin must not be resurrected")
	}
	if getStatus(t, handler) {
		t.Error("populated store: want needsSetup=false")
	}

	// delete the last user: store is empty, setup is needed again
	w = demotest.PostForm(handler, "/admin2/delete", url.Values{}, nil)
	if !strings.Contains(w.Body.String(), "Deleted user admin2") {
		t.Fatalf("delete admin2: body=%q", w.Body.String())
	}
	if !getStatus(t, handler) {
		t.Error("empty store: want needsSetup=true")
	}

	// now bootstrap seeds again
	w = demotest.PostForm(handler, "/run", url.Values{}, nil)
	if !strings.Contains(w.Body.String(), "seeded") {
		t.Errorf("bootstrap on empty store: want seeded message, got %q", w.Body.String())
	}
	if getStatus(t, handler) {
		t.Error("after re-seed: want needsSetup=false")
	}
}
