package basicauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/basicauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"github.com/go-bumbu/userauth/service/throttle"
	throttlememory "github.com/go-bumbu/userauth/service/throttle/store/memory"
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

func TestThrottle(t *testing.T) {
	newThrottled := func() *basicauth.AuthHandler {
		return basicauth.NewThrottledHandler(dummyUser{}, "", false, &throttle.Backoff{
			Store:        throttlememory.New(),
			FreeFailures: 1,
			BaseDelay:    time.Hour, // effectively "until the test ends"
		}, nil)
	}

	t.Run("wrong passwords throttle even the correct one", func(t *testing.T) {
		auth := newThrottled()
		for i := 0; i < 2; i++ {
			if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "wrong")); loggedIn {
				t.Fatal("wrong password must not log in")
			}
		}
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "admin")); loggedIn {
			t.Fatal("throttled request must be a credential failure, even with correct credentials")
		}
	})

	t.Run("unknown usernames throttle like existing ones", func(t *testing.T) {
		auth := basicauth.NewThrottledHandler(fakeUserStore{err: userauth.ErrUserNotFound}, "", false, &throttle.Backoff{
			Store:        throttlememory.New(),
			FreeFailures: 1,
			BaseDelay:    time.Hour,
		}, nil)
		respRec := httptest.NewRecorder()
		for i := 0; i < 3; i++ {
			if loggedIn, _ := auth.HandleAuth(respRec, basicAuthReq("ghost", "guess")); loggedIn {
				t.Fatal("unknown user must not log in")
			}
		}
		// throttled requests stay plain credential failures: no 5xx, no signal
		if respRec.Result().StatusCode == http.StatusInternalServerError {
			t.Fatal("throttling must not surface as an internal error")
		}
	})

	t.Run("success resets the count", func(t *testing.T) {
		// budget of 2: one failure leaves the account usable
		auth := basicauth.NewThrottledHandler(dummyUser{}, "", false, &throttle.Backoff{
			Store:        throttlememory.New(),
			FreeFailures: 2,
			BaseDelay:    time.Hour,
		}, nil)
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "wrong")); loggedIn {
			t.Fatal("wrong password must not log in")
		}
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "admin")); !loggedIn {
			t.Fatal("one failure is within the free budget; correct login should pass")
		}
		// the reset gives a fresh free failure
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "wrong")); loggedIn {
			t.Fatal("wrong password must not log in")
		}
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "admin")); !loggedIn {
			t.Fatal("correct login after reset should pass")
		}
	})

	t.Run("usernames throttle independently", func(t *testing.T) {
		auth := newThrottled()
		for i := 0; i < 2; i++ {
			_, _ = auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("admin", "wrong"))
		}
		// "admin" is throttled now, a different username is not (dummyUser
		// treats every username as admin/admin, so "other" can still log in)
		if loggedIn, _ := auth.HandleAuth(httptest.NewRecorder(), basicAuthReq("other", "admin")); !loggedIn {
			t.Fatal("failures for one username must not throttle another")
		}
	})
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
