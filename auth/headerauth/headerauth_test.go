package headerauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/go-bumbu/userauth/auth/headerauth"
	"github.com/google/go-cmp/cmp"
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

	headerAuth := headerauth.New(headerauth.Cfg{Enforce: true})

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

func TestGroupsParsing(t *testing.T) {
	tcs := []struct {
		name     string
		cfg      headerauth.Cfg
		headers  map[string]string
		expected headerauth.RequestData
	}{
		{
			name: "groups parsed from default header",
			cfg:  headerauth.Cfg{ParseGroups: true},
			headers: map[string]string{
				headerauth.UserAuthHeader:   "user1",
				headerauth.GroupsAuthHeader: "admin, staff ,dev",
			},
			expected: headerauth.RequestData{UserName: "user1", Groups: []string{"admin", "staff", "dev"}},
		},
		{
			name: "custom header names and separator",
			cfg:  headerauth.Cfg{UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", GroupsSep: ";", ParseGroups: true},
			headers: map[string]string{
				"Remote-User":   "alice",
				"Remote-Groups": "aether-admin;users",
			},
			expected: headerauth.RequestData{UserName: "alice", Groups: []string{"aether-admin", "users"}},
		},
		{
			name: "groups ignored when parsing disabled",
			cfg:  headerauth.Cfg{},
			headers: map[string]string{
				headerauth.UserAuthHeader:   "user1",
				headerauth.GroupsAuthHeader: "admin",
			},
			expected: headerauth.RequestData{UserName: "user1"},
		},
		{
			name: "empty and whitespace-only entries dropped",
			cfg:  headerauth.Cfg{ParseGroups: true},
			headers: map[string]string{
				headerauth.UserAuthHeader:   "user1",
				headerauth.GroupsAuthHeader: "admin,, ,dev",
			},
			expected: headerauth.RequestData{UserName: "user1", Groups: []string{"admin", "dev"}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			h := headerauth.New(tc.cfg)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got := h.GetData(req)
			if diff := cmp.Diff(tc.expected, got); diff != "" {
				t.Errorf("request data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestContextInjection(t *testing.T) {
	h := headerauth.New(headerauth.Cfg{ParseGroups: true})

	var got headerauth.RequestData
	var gotErr error
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotErr = headerauth.CtxGetRequestData(r)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerauth.UserAuthHeader, "user1")
	req.Header.Set(headerauth.GroupsAuthHeader, "admin,dev")

	h.Middleware(inner).ServeHTTP(httptest.NewRecorder(), req)

	if gotErr != nil {
		t.Fatalf("unexpected error reading context: %s", gotErr)
	}
	want := headerauth.RequestData{UserName: "user1", Groups: []string{"admin", "dev"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("context data mismatch (-want +got):\n%s", diff)
	}

	t.Run("no data without HandleAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := headerauth.CtxGetRequestData(req)
		if err == nil {
			t.Error("expected error reading identity from a request that did not pass HandleAuth")
		}
	})
}

func TestTrustedProxies(t *testing.T) {
	tcs := []struct {
		name           string
		trusted        []netip.Prefix
		remoteAddr     string
		expectedStatus int
	}{
		{
			name:           "peer inside trusted range is honored",
			trusted:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			remoteAddr:     "10.1.2.3:41000",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "peer outside trusted range is rejected",
			trusted:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			remoteAddr:     "192.168.1.50:41000",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "empty trust list honors every peer",
			trusted:        nil,
			remoteAddr:     "192.168.1.50:41000",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "ipv4-mapped ipv6 peer matches ipv4 range",
			trusted:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			remoteAddr:     "[::ffff:10.1.2.3]:41000",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			h := headerauth.New(headerauth.Cfg{TrustedProxies: tc.trusted})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(headerauth.UserAuthHeader, "user1")
			req.RemoteAddr = tc.remoteAddr

			respRec := httptest.NewRecorder()
			h.Middleware(dummyHandler()).ServeHTTP(respRec, req)

			if respRec.Result().StatusCode != tc.expectedStatus {
				t.Errorf("got unexpected response code expected: %d, got: %d",
					tc.expectedStatus, respRec.Result().StatusCode)
			}
		})
	}
}

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//w.WriteHeader(statusCode)
		_, _ = fmt.Fprint(w, "protected")
	})
}
