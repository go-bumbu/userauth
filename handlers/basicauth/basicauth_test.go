package basicauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/basicauth"
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
		st.pass = userauth.MustHashPw("admin")
	}
	return userauth.User{
		Id:      st.user,
		HashPw:  st.pass,
		Enabled: true,
	}, nil
}

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(statusCode)
		fmt.Fprint(w, "protected")
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

	basicAuth := basicauth.NewHandler(userauth.LoginHandler{
		UserStore: dummyUser{},
	}, "", true, nil)

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
