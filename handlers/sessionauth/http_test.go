package sessionauth_test

import (
	"bytes"
	"github.com/go-bumbu/userauth"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestJsonAuthHandler(t *testing.T) {

	tcs := []struct {
		name     string
		password string
		expect   int
	}{
		{
			name:     "valid login",
			password: "admin",
			expect:   200,
		},
		{
			name:     "invalid login",
			password: "nope",
			expect:   401,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, useFsStore)
			defer svr.Close()

			// perform login
			var jsonStr = []byte(`{"user":"admin","password":"` + tc.password + `"}`)
			request, err := http.NewRequest("POST", svr.URL+"/json-login", bytes.NewBuffer(jsonStr))
			request.Header.Set("Content-Type", "application/json")

			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}

			want := tc.expect
			if response.StatusCode != want {
				t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, response.StatusCode)
			}
		})
	}
}

func TestFormAuthHandler(t *testing.T) {

	tcs := []struct {
		name     string
		password string
		expect   int
	}{
		{
			name:     "valid login",
			password: "admin",
			expect:   200,
		},
		{
			name:     "invalid login",
			password: "nope",
			expect:   401,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, useFsStore)
			defer svr.Close()

			// perform login
			var param = url.Values{}

			param.Set("user", "admin")
			param.Set("password", tc.password)

			var payload = bytes.NewBufferString(param.Encode())
			request, err := http.NewRequest("POST", svr.URL+"/form-login", payload)

			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}

			want := tc.expect
			if response.StatusCode != want {
				t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, response.StatusCode)
			}
		})
	}
}

func TestSessionManagement(t *testing.T) {

	// more stores to come...
	stores := []string{
		useFsStore,
	}

	for _, storeType := range stores {
		t.Run(storeType, func(t *testing.T) {
			t.Parallel()

			t.Run("access resource after login", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 200*time.Millisecond, 0, storeType)
				defer svr.Close()

				// assert first request is not logged in
				resp := doReq(c, svr.URL+"/something", t)
				want := http.StatusUnauthorized
				if resp.StatusCode != want {
					t.Errorf("[first request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// perform login
				resp = doReq(c, svr.URL+"/login", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			// this tests asserts that we get a 401 after the session is expired
			t.Run("401 after session expired", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 500*time.Millisecond, 0, storeType)
				defer svr.Close()
				// perform login
				resp := doReq(c, svr.URL+"/login", t)
				want := http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[first request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep longer than the 50ms expiry
				time.Sleep(100 * time.Millisecond)
				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusUnauthorized
				if resp.StatusCode != want {
					t.Errorf("[second request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			// in this test we make multiple requests that keep the session active
			// while the overall session expiry is shorter that the total sleep time
			t.Run("renew session", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 2000*time.Millisecond, 1*time.Millisecond, storeType)
				defer svr.Close()
				// perform login
				resp := doReq(c, svr.URL+"/login", t)
				want := http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep a bit and renew the session
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				// another request renewing the session
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)

				// sleep another bit and renew the session
				time.Sleep(20 * time.Millisecond)
				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[third request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			// this test asserts that we get a 401 once we reach the max sess duration even if we keep updating the session
			t.Run("401 after max session duration", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 60*time.Millisecond, 0, storeType)
				defer svr.Close()
				// perform login
				resp := doReq(c, svr.URL+"/login", t)
				want := http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// delay 80ms
				for i := 0; i < 4; i++ {
					// sleep a bit and renew the session
					time.Sleep(20 * time.Millisecond)
					doReq(c, svr.URL+"/something", t)
				}

				// assert user gets 401
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusUnauthorized
				if resp.StatusCode != want {
					t.Errorf("[second request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			// this test expects verifies the session write throttling
			// it expects a 401 even if we keep updating the session > 50ms because the timestamp is never updated.
			t.Run("401 forced session to not be updated", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, storeType)
				defer svr.Close()
				// perform login
				resp := doReq(c, svr.URL+"/login", t)
				want := http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep a bit and  trigger a session renew, this is not exercised
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)

				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)

				// sleep another bit and check that session was not renewed
				time.Sleep(20 * time.Millisecond)
				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusUnauthorized
				if resp.StatusCode != want {
					t.Errorf("[second request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})
		})
	}

}

// test server  ------------------------------------------------------------
const useFsStore = "fs"

func testServer(SessionDur, MaxSessionDur, update time.Duration, storeType string) (*httptest.Server, *http.Client) {
	var store sessions.Store
	if storeType == useFsStore {
		store, _ = sessionauth.NewFsStore("", securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	}

	authSess, err := sessionauth.New(sessionauth.Cfg{
		Store:         store,
		SessionDur:    SessionDur,
		MaxSessionDur: MaxSessionDur,
		MinWriteSpace: update,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/login" {
			err = authSess.LoginUser(r, w, "tester")
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "ok", http.StatusOK)
		} else if r.RequestURI == "/form-login" {
			auth := userauth.LoginHandler{
				UserStore: dummyUser{},
			}
			handler := sessionauth.FormAuthHandler(authSess, auth)
			handler.ServeHTTP(w, r)
		} else if r.RequestURI == "/json-login" {
			auth := userauth.LoginHandler{
				UserStore: dummyUser{},
			}
			handler := sessionauth.JsonAuthHandler(authSess, auth)
			handler.ServeHTTP(w, r)
		} else {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "ok", http.StatusOK)
			})
			handler := authSess.Middleware(h)
			handler.ServeHTTP(w, r)
		}
	})

	svr := httptest.NewServer(handler)

	jar, _ := cookiejar.New(nil)
	c := svr.Client()
	c.Jar = jar

	return svr, c
}

func getTime(add string) time.Time {
	if add == "" {
		add = "0s"
	}
	dur, err := time.ParseDuration(add)
	if err != nil {
		panic(err)
	}

	return time.Now().Add(dur)
}
