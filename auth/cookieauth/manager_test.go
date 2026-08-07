package cookieauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// fakeStore is a sessions.Store that can fail on Get or Save to exercise error branches.
type fakeStore struct {
	getErr  error
	saveErr error
	saveOK  int // number of initial Save calls that succeed before saveErr is returned
	session *sessions.Session
}

func (s *fakeStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.New(r, name)
}

func (s *fakeStore) New(_ *http.Request, name string) (*sessions.Session, error) {
	if s.session == nil {
		s.session = sessions.NewSession(s, name)
		s.session.IsNew = true
	}
	return s.session, nil
}

func (s *fakeStore) Save(_ *http.Request, _ http.ResponseWriter, _ *sessions.Session) error {
	if s.saveErr == nil {
		return nil
	}
	if s.saveOK > 0 {
		s.saveOK--
		return nil
	}
	return s.saveErr
}

// newManager creates a Manager backed by a real cookie store.
func newManager(t *testing.T, cfg cookieauth.Cfg) *cookieauth.Manager {
	t.Helper()
	if cfg.Store == nil {
		store, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Store = store
	}
	m, err := cookieauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// loginAndCookie logs the user in and returns a new request carrying the session cookie.
func loginAndCookie(t *testing.T, m *cookieauth.Manager, user string) *http.Request {
	t.Helper()
	loginReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := m.LoginUser(loginReq, rec, user, true); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := http.Response{Header: rec.Header()}
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestNew(t *testing.T) {
	t.Run("nil store returns error", func(t *testing.T) {
		_, err := cookieauth.New(cookieauth.Cfg{})
		if err == nil {
			t.Fatal("expected an error on nil store, got nil")
		}
		if !strings.Contains(err.Error(), "store cannot be nil") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("custom config is accepted", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{
			SessionDur:    time.Minute,
			MaxSessionDur: time.Hour,
			MinWriteSpace: time.Second,
			CookieName:    "custom_cookie",
			AllowRenew:    true,
		})
		if m == nil {
			t.Fatal("expected a manager instance, got nil")
		}
	})
}

func TestManagerName(t *testing.T) {
	m := newManager(t, cookieauth.Cfg{})
	if got := m.Name(); got != cookieauth.SessionMngrName {
		t.Errorf("expected name %q, got %q", cookieauth.SessionMngrName, got)
	}
}

func TestHandleAuthErrors(t *testing.T) {
	t.Run("500 when session write fails on expiry update", func(t *testing.T) {
		store := &fakeStore{saveErr: errors.New("save failed"), saveOK: 1}
		m := newManager(t, cookieauth.Cfg{Store: store, MinWriteSpace: time.Nanosecond})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		if err := m.LoginUser(req, rec, "tester", true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)

		rec = httptest.NewRecorder()
		allow, stop := m.HandleAuth(rec, req)
		if allow || stop {
			t.Errorf("expected allow=false stop=false, got allow=%v stop=%v", allow, stop)
		}
		if rec.Result().StatusCode != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", rec.Result().StatusCode)
		}
	})

	t.Run("undecodable cookie is treated as no session", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name: cookieauth.DefaultCookieName, Value: "garbage",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})

		rec := httptest.NewRecorder()
		allow, stop := m.HandleAuth(rec, req)
		if allow || stop {
			t.Errorf("expected allow=false stop=false, got allow=%v stop=%v", allow, stop)
		}
		if rec.Result().StatusCode != http.StatusOK {
			t.Errorf("expected no error written, got status %d", rec.Result().StatusCode)
		}
	})
}

func TestLoginUser(t *testing.T) {
	t.Run("store get error is returned", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{Store: &fakeStore{getErr: errors.New("boom")}})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := m.LoginUser(req, httptest.NewRecorder(), "tester", true)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("renew is disabled when manager disallows it", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{AllowRenew: false})
		req := loginAndCookie(t, m, "tester")
		data, err := m.GetSessData(req)
		if err != nil {
			t.Fatal(err)
		}
		if data.RenewExpiration {
			t.Error("expected RenewExpiration to be forced to false")
		}
		if !data.IsAuthenticated || data.UserId != "tester" {
			t.Errorf("unexpected session data: %+v", data)
		}
	})
}

func TestGet(t *testing.T) {
	t.Run("decode error returns fresh session", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name: cookieauth.DefaultCookieName, Value: "not-a-valid-cookie",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})

		session, err := m.Get(req, cookieauth.DefaultCookieName)
		if err != nil {
			t.Fatalf("expected decode error to be swallowed, got: %v", err)
		}
		if session == nil {
			t.Fatal("expected a fresh session, got nil")
		}
	})

	t.Run("other store errors are returned", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{Store: &fakeStore{getErr: errors.New("boom")}})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		session, err := m.Get(req, cookieauth.DefaultCookieName)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if session != nil {
			t.Errorf("expected nil session on error, got: %+v", session)
		}
	})
}

func TestLogoutUser(t *testing.T) {
	t.Run("logout clears the session", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{})
		req := loginAndCookie(t, m, "tester")

		rec := httptest.NewRecorder()
		if err := m.LogoutUser(req, rec); err != nil {
			t.Fatal(err)
		}

		loggedOutReq := httptest.NewRequest(http.MethodGet, "/", nil)
		resp := http.Response{Header: rec.Header()}
		for _, c := range resp.Cookies() {
			loggedOutReq.AddCookie(c)
		}
		data, err := m.GetSessData(loggedOutReq)
		if err != nil {
			t.Fatal(err)
		}
		if data.IsAuthenticated {
			t.Error("expected session to be unauthenticated after logout")
		}
	})

	t.Run("store get error is returned", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{Store: &fakeStore{getErr: errors.New("boom")}})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := m.LogoutUser(req, httptest.NewRecorder()); err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
}

func TestTouchSession(t *testing.T) {
	t.Run("renews an authenticated session", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{AllowRenew: true, MinWriteSpace: time.Nanosecond})
		req := loginAndCookie(t, m, "tester")
		time.Sleep(time.Millisecond)

		rec := httptest.NewRecorder()
		if err := m.TouchSession(req, rec); err != nil {
			t.Fatal(err)
		}
		if rec.Header().Get("Set-Cookie") == "" {
			t.Error("expected the session cookie to be re-written")
		}
	})

	t.Run("no-op without an authenticated session", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		if err := m.TouchSession(req, rec); err != nil {
			t.Fatal(err)
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Error("expected no cookie to be written for unauthenticated request")
		}
	})
}

func TestGetSessData(t *testing.T) {
	t.Run("returns stored session data", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{})
		req := loginAndCookie(t, m, "tester")
		data, err := m.GetSessData(req)
		if err != nil {
			t.Fatal(err)
		}
		if !data.IsAuthenticated || data.UserId != "tester" {
			t.Errorf("unexpected session data: %+v", data)
		}
	})

	t.Run("expired session is reported unauthenticated", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{SessionDur: time.Millisecond})
		req := loginAndCookie(t, m, "tester")
		time.Sleep(5 * time.Millisecond)
		data, err := m.GetSessData(req)
		if err != nil {
			t.Fatal(err)
		}
		if data.IsAuthenticated {
			t.Error("expected expired session to be unauthenticated")
		}
	})

	t.Run("failing store yields empty data without error", func(t *testing.T) {
		m := newManager(t, cookieauth.Cfg{Store: &fakeStore{getErr: errors.New("boom")}})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data, err := m.GetSessData(req)
		if err != nil {
			t.Fatalf("expected store errors to be swallowed, got: %v", err)
		}
		if data.IsAuthenticated || data.UserId != "" {
			t.Errorf("expected empty session data, got: %+v", data)
		}
	})
}
