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
	"github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/flow/login/handlers"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
)

// failingUsers simulates a broken user store: every lookup errors.
type failingUsers struct{}

func (failingUsers) GetUser(string) (userauth.User, error) {
	return userauth.User{}, errors.New("user store down")
}

func (failingUsers) GetUserByLogin(string) (userauth.User, error) {
	return userauth.User{}, errors.New("user store down")
}

// failingTOTP simulates a broken TOTP factor: every lookup errors, so the
// policy cannot decide whether to demand a code.
type failingTOTP struct{}

func (failingTOTP) Verify(string, string) (bool, error) {
	return false, errors.New("totp store down")
}

func (failingTOTP) Enabled(string) (bool, error) {
	return false, errors.New("totp store down")
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

func postRaw(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestJSONMalformedRequests(t *testing.T) {
	t.Run("invalid JSON body is 400 on every endpoint", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		for name, h := range map[string]http.Handler{
			"login":        j.LoginHandler(),
			"verify":       j.VerifyHandler(),
			"request-code": j.RequestCodeHandler(),
		} {
			if w := postRaw(t, h, "{not json"); w.Code != http.StatusBadRequest {
				t.Errorf("%s: want 400, got %d", name, w.Code)
			}
		}
	})

	t.Run("verify with missing fields is 400", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		for name, p := range map[string]handlers.VerifyPayload{
			"no method or code": {User: "plain"},
			"no code":           {User: "plain", Method: "totp"},
			"no user":           {Method: "totp", Code: "123456"},
		} {
			if w := postJSON(t, j.VerifyHandler(), p); w.Code != http.StatusBadRequest {
				t.Errorf("%s: want 400, got %d", name, w.Code)
			}
		}
	})

	t.Run("request-code without username is 400", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		if w := postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{}); w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	t.Run("request-code for a method without delivery is 400", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		p := handlers.RequestCodePayload{User: "plain", Method: "password"}
		if w := postJSON(t, j.RequestCodeHandler(), p); w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	t.Run("request-code for an unregistered method is 400", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		p := handlers.RequestCodePayload{User: "plain", Method: "sms"}
		if w := postJSON(t, j.RequestCodeHandler(), p); w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})
}

func TestJSONInternalErrors(t *testing.T) {
	t.Run("user store failure at login is 500", func(t *testing.T) {
		j := handlers.NewPasswordTOTP(handlers.PasswordTOTPCfg{
			Users:    failingUsers{},
			Session:  &captureLogin{},
			Attempts: memory.New(),
			Logger:   discardLogger(),
		})
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "any", Password: "pw"})
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "internal error") {
			t.Errorf("want generic error body, got %s", w.Body.String())
		}
	})

	t.Run("totp store failure after the password step is 500", func(t *testing.T) {
		users := &staticusers.Users{Users: []staticusers.User{
			{Id: "plain", HashPw: hashutil.MustHashPassword("plain-pw"), Enabled: true},
		}}
		j := handlers.NewPasswordTOTP(handlers.PasswordTOTPCfg{
			Users:    users,
			Session:  &captureLogin{},
			Attempts: memory.New(),
			TOTP:     failingTOTP{},
			Logger:   discardLogger(),
		})
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "plain", Password: "plain-pw"})
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("user store failure at request-code is 500", func(t *testing.T) {
		j := handlers.NewEmailCode(handlers.EmailCodeCfg{
			Users:   failingUsers{},
			Codes:   verificationcode.NewService(csmemory.New(), verificationcode.Opts{}),
			Deliver: &captureDeliverer{},
			Session: &captureLogin{},
			Logger:  discardLogger(),
		})
		w := postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{User: "demo@example.com"})
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestJSONWriteFailure(t *testing.T) {
	// A broken response writer must not panic; the status still goes out even
	// when the body cannot be written. The fixture has no Logger, exercising
	// the slog.Default fallback.
	j, _ := passwordTOTPFixture()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := &failingWriter{}
	j.LoginHandler().ServeHTTP(w, req)
	if w.status != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.status)
	}
}
