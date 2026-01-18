package headerauth_test

import (
	"fmt"
	"github.com/go-bumbu/userauth/handlers/headerauth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHttpHeaderResponseCode(t *testing.T) {

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
			name: "expect 200 on correct credentials",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/bla", nil)
				req.Header.Set(headerauth.UserAuthHeader, "user1")
				// set auth header
				return req
			},
			expectedStatusCode: http.StatusOK,
		},
	}

	dummy := dummyHandler()

	headerAuth := headerauth.New(headerauth.UserAuthHeader, true, nil)

	handler := headerAuth.Middleware(dummy)

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

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(statusCode)
		fmt.Fprint(w, "protected")
	})
}
