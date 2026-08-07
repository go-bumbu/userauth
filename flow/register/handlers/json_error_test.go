package handlers_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/register"
	"github.com/go-bumbu/userauth/flow/register/handlers"
	"github.com/go-bumbu/userauth/flow/register/pendingstore/memory"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
)

// failingUsers simulates a broken user store: every lookup errors.
type failingUsers struct{}

func (failingUsers) GetUser(string) (userauth.User, error) {
	return userauth.User{}, errors.New("user store down")
}

func (failingUsers) GetUserByLogin(string) (userauth.User, error) {
	return userauth.User{}, errors.New("user store down")
}

// failingWriter is a ResponseWriter whose body writes always fail, as when
// the client hangs up mid-response.
type failingWriter struct {
	header http.Header
	status int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *failingWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

func (w *failingWriter) WriteHeader(status int) { w.status = status }

// discardLogger keeps the deliberately provoked errors out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func postRaw(t *testing.T, h http.Handler, body string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result().StatusCode
}

func TestJSONMalformedRequests(t *testing.T) {
	t.Run("invalid JSON body is 400 on every endpoint", func(t *testing.T) {
		f := newFixture(withEmail)
		for name, h := range map[string]http.Handler{
			"register":     f.json.RegisterHandler(),
			"verify":       f.json.VerifyHandler(),
			"request-code": f.json.RequestCodeHandler(),
		} {
			if status := postRaw(t, h, "{not json"); status != http.StatusBadRequest {
				t.Errorf("%s: want 400, got %d", name, status)
			}
		}
	})

	t.Run("verify with missing fields is 400", func(t *testing.T) {
		f := newFixture(withEmail)
		for name, payload := range map[string]map[string]string{
			"no check or code": {"username": "alice"},
			"no code":          {"username": "alice", "check": "email"},
			"no user":          {"check": "email", "code": "123456"},
		} {
			status, _ := post(t, f.json.VerifyHandler(), payload)
			if status != http.StatusBadRequest {
				t.Errorf("%s: want 400, got %d", name, status)
			}
		}
	})

	t.Run("request-code without username is 400", func(t *testing.T) {
		f := newFixture(withEmail)
		status, _ := post(t, f.json.RequestCodeHandler(), map[string]string{})
		if status != http.StatusBadRequest {
			t.Errorf("want 400, got %d", status)
		}
	})

	t.Run("request-code for an unregistered check is 400", func(t *testing.T) {
		f := newFixture(withEmail)
		status, _ := post(t, f.json.RequestCodeHandler(), map[string]string{
			"username": "alice", "check": "sms",
		})
		if status != http.StatusBadRequest {
			t.Errorf("want 400, got %d", status)
		}
	})
}

func TestJSONInternalErrors(t *testing.T) {
	t.Run("user store failure at register is 500", func(t *testing.T) {
		f := newFixture(func(f *fixture, cfg *handlers.Cfg) {
			cfg.Users = failingUsers{}
			cfg.Logger = discardLogger()
		})
		status, body := post(t, f.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw",
		})
		if status != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d %v", status, body)
		}
		if body["error"] != "internal error" {
			t.Errorf("want generic error body, got %v", body)
		}
	})

	t.Run("misconfigured flow at request-code is 500", func(t *testing.T) {
		// An email check without a Pending store is a misconfiguration:
		// Flow.Initiate returns an error and the handler reports 500.
		j := &handlers.JSON{
			Flow: &register.Flow{
				Users:   &fakeUsers{},
				Creator: &captureCreator{},
				Checks: []register.Check{register.EmailCheck{
					Codes:   verificationcode.NewService(csmemory.New(), verificationcode.Opts{}),
					Deliver: &captureDeliverer{},
				}},
			},
			Logger: discardLogger(),
		}
		status, body := post(t, j.RequestCodeHandler(), map[string]string{"username": "alice"})
		if status != http.StatusInternalServerError || body["error"] != "internal error" {
			t.Fatalf("want generic 500, got %d %v", status, body)
		}
	})

	t.Run("user store failure at verify is 500", func(t *testing.T) {
		pending := memory.New()
		codes := verificationcode.NewService(csmemory.New(), verificationcode.Opts{})
		deliverer := &captureDeliverer{}

		// Start against a healthy store so a pending registration exists...
		healthy := newFixture(func(f *fixture, cfg *handlers.Cfg) {
			cfg.Pending = pending
			cfg.Codes = codes
			cfg.Deliver = deliverer
		})
		if status, _ := post(t, healthy.json.RegisterHandler(), map[string]string{
			"username": "alice", "password": "pw", "email": "alice@example.com",
		}); status != http.StatusOK {
			t.Fatalf("start failed with %d", status)
		}

		// ...then verify while the user store is down: the availability
		// re-check inside finish fails internally.
		broken := newFixture(func(f *fixture, cfg *handlers.Cfg) {
			cfg.Users = failingUsers{}
			cfg.Pending = pending
			cfg.Codes = codes
			cfg.Deliver = deliverer
			cfg.Logger = discardLogger()
		})
		status, body := post(t, broken.json.VerifyHandler(), map[string]string{
			"username": "alice", "check": "email", "code": deliverer.code,
		})
		if status != http.StatusInternalServerError || body["error"] != "internal error" {
			t.Fatalf("want generic 500, got %d %v", status, body)
		}
	})
}

func TestJSONWriteFailure(t *testing.T) {
	// A broken response writer must not panic; the status still goes out even
	// when the body cannot be written. The fixture has no Logger, exercising
	// the slog.Default fallback.
	f := newFixture(nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := &failingWriter{}
	f.json.RegisterHandler().ServeHTTP(w, r)
	if w.status != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.status)
	}
}
