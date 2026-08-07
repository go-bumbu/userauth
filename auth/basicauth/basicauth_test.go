package basicauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/basicauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
)

type dummyUser struct {
	user string
	pass string
}

func (st dummyUser) GetUser(id string) (userauth.User, error) {
	if st.user == "" {
		st.user = "admin"
	}
	if st.pass == "" {
		st.pass = hashutil.MustHashPassword("admin")
	}
	return userauth.User{
		ID:      st.user,
		LoginID: st.user,
		HashPw:  st.pass,
		Enabled: true,
	}, nil
}

func (st dummyUser) GetUserByLogin(loginID string) (userauth.User, error) {
	return st.GetUser(loginID)
}

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(statusCode)
		_, _ = fmt.Fprint(w, "protected")
	})
}

func TestBasicAuthResponseCode(t *testing.T) {

	tcs := []struct {
		name               string
		request            func() *http.Request
		expectedStatusCode int
	}{
		{
			name: "expect 401 without auth info",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/bla", nil)
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "expect 401 on wrong auth credentials",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/bla", nil)
				req.SetBasicAuth("admin", "wrong")
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "expect 200 on correct credentials",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/bla", nil)
				req.SetBasicAuth("admin", "admin")
				return req
			},
			expectedStatusCode: http.StatusOK,
		},
	}

	dummy := dummyHandler()

	basicAuth := basicauth.NewHandler(dummyUser{}, "", true, nil)

	handler := basicAuth.Middleware(dummy)

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			mux := http.NewServeMux()
			mux.Handle("GET /", handler)

			respRec := httptest.NewRecorder()
			mux.ServeHTTP(respRec, tc.request())
			resp := respRec.Result()

			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("got unexpected response code expected: %d, got: %d", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

// fakeUserStore returns a fixed user or error, allowing to exercise all verify branches.
type fakeUserStore struct {
	user userauth.User
	err  error
}

func (st fakeUserStore) GetUser(_ string) (userauth.User, error) {
	return st.user, st.err
}

func (st fakeUserStore) GetUserByLogin(loginID string) (userauth.User, error) {
	return st.GetUser(loginID)
}

func TestName(t *testing.T) {
	basicAuth := basicauth.NewHandler(dummyUser{}, "", false, nil)
	if got := basicAuth.Name(); got != "basicauth" {
		t.Errorf("expected handler name %q, got: %q", "basicauth", got)
	}
}

func basicAuthReq(user, pass string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/bla", nil)
	req.SetBasicAuth(user, pass)
	return req
}

func TestHandleAuth(t *testing.T) {
	enabledUser := userauth.User{
		ID: "admin", LoginID: "admin",
		HashPw:  hashutil.MustHashPassword("admin"),
		Enabled: true,
	}

	tcs := []struct {
		name           string
		store          userauth.UserGetter
		enforce        bool
		request        *http.Request
		wantLoggedIn   bool
		wantStop       bool
		wantStatusCode int
		wantAuthHeader bool
	}{
		{
			name:           "correct credentials, not enforced",
			store:          fakeUserStore{user: enabledUser},
			request:        basicAuthReq("admin", "admin"),
			wantLoggedIn:   true,
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "correct credentials, enforced sets WWW-Authenticate and stops evaluation",
			store:          fakeUserStore{user: enabledUser},
			enforce:        true,
			request:        basicAuthReq("admin", "admin"),
			wantLoggedIn:   true,
			wantStop:       true,
			wantStatusCode: http.StatusOK,
			wantAuthHeader: true,
		},
		{
			name:           "no auth header, not enforced",
			store:          fakeUserStore{user: enabledUser},
			request:        httptest.NewRequest(http.MethodGet, "/bla", nil),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "user not found is a credential failure",
			store:          fakeUserStore{err: userauth.ErrUserNotFound},
			request:        basicAuthReq("admin", "admin"),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "disabled user error is a credential failure",
			store:          fakeUserStore{err: userauth.ErrUserDisabled},
			request:        basicAuthReq("admin", "admin"),
			wantStatusCode: http.StatusOK,
		},
		{
			name: "disabled user flag is a credential failure",
			store: fakeUserStore{user: userauth.User{
				ID: "admin", LoginID: "admin",
				HashPw:  hashutil.MustHashPassword("admin"),
				Enabled: false,
			}},
			request:        basicAuthReq("admin", "admin"),
			wantStatusCode: http.StatusOK,
		},
		{
			name: "malformed stored hash is a credential failure",
			store: fakeUserStore{user: userauth.User{ //nolint:gosec // not a credential, malformed-hash fixture
				ID: "admin", LoginID: "admin",
				HashPw:  "not-a-valid-hash",
				Enabled: true,
			}},
			request:        basicAuthReq("admin", "admin"),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "internal store error returns 500",
			store:          fakeUserStore{err: errors.New("db is down")},
			request:        basicAuthReq("admin", "admin"),
			wantStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			basicAuth := basicauth.NewHandler(tc.store, "", tc.enforce, nil)
			respRec := httptest.NewRecorder()

			loggedIn, stop := basicAuth.HandleAuth(respRec, tc.request)

			if loggedIn != tc.wantLoggedIn {
				t.Errorf("expected loggedIn: %v, got: %v", tc.wantLoggedIn, loggedIn)
			}
			if stop != tc.wantStop {
				t.Errorf("expected stopEvaluation: %v, got: %v", tc.wantStop, stop)
			}

			resp := respRec.Result()
			if resp.StatusCode != tc.wantStatusCode {
				t.Errorf("expected status code: %d, got: %d", tc.wantStatusCode, resp.StatusCode)
			}
			gotHeader := resp.Header.Get("WWW-Authenticate") != ""
			if gotHeader != tc.wantAuthHeader {
				t.Errorf("expected WWW-Authenticate header presence: %v, got: %v", tc.wantAuthHeader, gotHeader)
			}
		})
	}
}
