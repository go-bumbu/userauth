package cookieauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bumbu/userauth/auth/cookieauth"
)

type fakeLogout struct {
	err error
}

func (f fakeLogout) LogoutUser(_ *http.Request, _ http.ResponseWriter) error {
	return f.err
}

func TestLogoutHandler(t *testing.T) {
	tcs := []struct {
		name         string
		logOuter     cookieauth.UserLogout
		redirect     string
		wantStatus   int
		wantLocation string
	}{
		{
			name:       "logout without redirect",
			logOuter:   fakeLogout{},
			wantStatus: http.StatusOK,
		},
		{
			name:         "logout with redirect",
			logOuter:     fakeLogout{},
			redirect:     "/login",
			wantStatus:   http.StatusSeeOther,
			wantLocation: "/login",
		},
		{
			name:       "logout error returns 500",
			logOuter:   fakeLogout{err: errors.New("boom")},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			handler := cookieauth.LogoutHandler(tc.logOuter, tc.redirect)
			req := httptest.NewRequest(http.MethodGet, "/logout", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			resp := rec.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); got != tc.wantLocation {
				t.Errorf("expected Location header %q, got %q", tc.wantLocation, got)
			}
		})
	}
}

func TestLogoutHandlerWithManager(t *testing.T) {
	m := newManager(t, cookieauth.Cfg{})
	req := loginAndCookie(t, m, "tester")
	req.RequestURI = "/logout"

	rec := httptest.NewRecorder()
	cookieauth.LogoutHandler(m, "").ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Result().StatusCode)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Error("expected the session cookie to be re-written on logout")
	}
}
