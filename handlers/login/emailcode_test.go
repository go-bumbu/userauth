package login_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	loginhandler "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	vcmemory "github.com/go-bumbu/userauth/verificationcode/memory"
)

// captureDeliverer records the last delivered code instead of sending it.
type captureDeliverer struct {
	to   string
	code string
}

func (d *captureDeliverer) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	d.to = to
	d.code = code
	return nil
}

// captureLogin records LoginUser calls instead of creating a real session.
type captureLogin struct {
	userID string
	called bool
}

func (l *captureLogin) LoginUser(_ *http.Request, _ http.ResponseWriter, userID string, _ bool) error {
	l.userID = userID
	l.called = true
	return nil
}

func emailCodeTestFlow() (*loginhandler.EmailCodeLogin, *captureDeliverer, *captureLogin) {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "demo@example.com", Enabled: true},
		{Id: "disabled@example.com", Enabled: false},
	}}
	codes := userauth.NewVerificationCodeService(vcmemory.New(), userauth.VerificationCodeOpts{})
	deliverer := &captureDeliverer{}
	session := &captureLogin{}
	flow := &loginhandler.EmailCodeLogin{
		Users:     users,
		Codes:     codes,
		Deliver:   deliverer,
		Auth:      &userauth.LoginHandler{EmailCode: codes},
		Session:   session,
		VerifyURL: "/login/verify",
	}
	return flow, deliverer, session
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestEmailCodeRequestHandler(t *testing.T) {
	t.Run("known enabled user gets a code delivered", func(t *testing.T) {
		flow, deliverer, _ := emailCodeTestFlow()
		w := postForm(t, flow.RequestHandler(), "/login", url.Values{"email": {"demo@example.com"}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("want 303, got %d", w.Code)
		}
		if deliverer.to != "demo@example.com" || deliverer.code == "" {
			t.Errorf("expected a code delivered to demo@example.com, got to=%q code=%q", deliverer.to, deliverer.code)
		}
		if loc := w.Header().Get("Location"); loc != "/login/verify?email=demo%40example.com" {
			t.Errorf("unexpected redirect: %q", loc)
		}
	})

	t.Run("unknown and disabled emails respond identically to known ones", func(t *testing.T) {
		flow, deliverer, _ := emailCodeTestFlow()
		known := postForm(t, flow.RequestHandler(), "/login", url.Values{"email": {"demo@example.com"}})
		for _, email := range []string{"nobody@example.com", "disabled@example.com"} {
			deliverer.to, deliverer.code = "", ""
			w := postForm(t, flow.RequestHandler(), "/login", url.Values{"email": {email}})
			if w.Code != known.Code {
				t.Errorf("%s: status %d differs from known-user status %d", email, w.Code, known.Code)
			}
			if deliverer.code != "" {
				t.Errorf("%s: no code should be delivered", email)
			}
		}
	})

	t.Run("empty email is a bad request", func(t *testing.T) {
		flow, _, _ := emailCodeTestFlow()
		w := postForm(t, flow.RequestHandler(), "/login", url.Values{})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", w.Code)
		}
	})
}

func TestEmailCodeVerifyHandler(t *testing.T) {
	requestCode := func(t *testing.T, flow *loginhandler.EmailCodeLogin, deliverer *captureDeliverer, email string) string {
		t.Helper()
		postForm(t, flow.RequestHandler(), "/login", url.Values{"email": {email}})
		if deliverer.code == "" {
			t.Fatal("no code delivered")
		}
		return deliverer.code
	}

	t.Run("valid code creates a session", func(t *testing.T) {
		flow, deliverer, session := emailCodeTestFlow()
		code := requestCode(t, flow, deliverer, "demo@example.com")
		w := postForm(t, flow.VerifyHandler(), "/login/verify",
			url.Values{"email": {"demo@example.com"}, "code": {code}})
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", w.Code)
		}
		if !session.called || session.userID != "demo@example.com" {
			t.Errorf("expected session for demo@example.com, got called=%v userID=%q", session.called, session.userID)
		}
	})

	t.Run("code is single use", func(t *testing.T) {
		flow, deliverer, session := emailCodeTestFlow()
		code := requestCode(t, flow, deliverer, "demo@example.com")
		form := url.Values{"email": {"demo@example.com"}, "code": {code}}
		postForm(t, flow.VerifyHandler(), "/login/verify", form)
		session.called = false
		w := postForm(t, flow.VerifyHandler(), "/login/verify", form)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("replayed code: want 401, got %d", w.Code)
		}
		if session.called {
			t.Error("replayed code must not create a session")
		}
	})

	t.Run("wrong code is unauthorized", func(t *testing.T) {
		flow, deliverer, session := emailCodeTestFlow()
		requestCode(t, flow, deliverer, "demo@example.com")
		w := postForm(t, flow.VerifyHandler(), "/login/verify",
			url.Values{"email": {"demo@example.com"}, "code": {"000000"}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
		if session.called {
			t.Error("wrong code must not create a session")
		}
	})

	t.Run("user disabled between request and verify is rejected", func(t *testing.T) {
		flow, deliverer, session := emailCodeTestFlow()
		code := requestCode(t, flow, deliverer, "demo@example.com")
		users := flow.Users.(*staticusers.Users)
		users.Users[0].Enabled = false
		w := postForm(t, flow.VerifyHandler(), "/login/verify",
			url.Values{"email": {"demo@example.com"}, "code": {code}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
		if session.called {
			t.Error("disabled user must not get a session")
		}
	})

	t.Run("missing fields are a bad request", func(t *testing.T) {
		flow, _, _ := emailCodeTestFlow()
		w := postForm(t, flow.VerifyHandler(), "/login/verify", url.Values{"email": {"demo@example.com"}})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", w.Code)
		}
	})
}
