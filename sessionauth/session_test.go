package sessionauth_test

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/go-bumbu/userauth/sessionauth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

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
				time.Sleep(40 * time.Millisecond)
				// assert user is still logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[first request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep another bit and renew the session
				time.Sleep(40 * time.Millisecond)
				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[second request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			t.Run("401 after max session duration", func(t *testing.T) {
				svr, c := testServer(500*time.Millisecond, 50*time.Millisecond, 0, storeType)
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

				// sleep longer than the 50ms max session duration
				time.Sleep(60 * time.Millisecond)
				// assert user is logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusUnauthorized
				if resp.StatusCode != want {
					t.Errorf("[second request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}
			})

			t.Run("401 forced session to not be updated", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, storeType)
				defer svr.Close()
				// perform login
				resp := doReq(c, svr.URL+"/login", t)
				want := http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep a bit and trigger a session renew, this is not exercised
				time.Sleep(40 * time.Millisecond)
				// assert user is still logged in
				resp = doReq(c, svr.URL+"/something", t)
				want = http.StatusOK
				if resp.StatusCode != want {
					t.Errorf("[first request] got unexpected response code expected: %d, got: %d", want, resp.StatusCode)
				}

				// sleep another bit and check that session was not renewed
				time.Sleep(40 * time.Millisecond)
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

func TestProcessSessionData(t *testing.T) {

	tcs := []struct {
		name string
		in   sessionauth.SessionData
		want sessionauth.SessionData
	}{
		{
			name: "session valid",
			in: sessionauth.SessionData{
				UserData: sessionauth.UserData{
					IsAuthenticated: true,
				},
				Expiration:  getTime("10m"),
				ForceReAuth: getTime("1m"),
			},
			want: sessionauth.SessionData{UserData: sessionauth.UserData{IsAuthenticated: true}},
		},
		{
			name: "session expired",
			in: sessionauth.SessionData{UserData: sessionauth.UserData{IsAuthenticated: true},
				Expiration: getTime("-1s"),
			},
			want: sessionauth.SessionData{UserData: sessionauth.UserData{IsAuthenticated: false}},
		},
		{
			name: "session NOT expired, but hard logout",
			in: sessionauth.SessionData{UserData: sessionauth.UserData{IsAuthenticated: true},
				Expiration:  getTime("10m"),
				ForceReAuth: getTime("-1s"),
			},
			want: sessionauth.SessionData{UserData: sessionauth.UserData{IsAuthenticated: false}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			got := tc.in
			got.Process(0)
			want := tc.want
			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(sessionauth.SessionData{}, "Expiration", "ForceReAuth")); diff != "" {
				t.Errorf("Content mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func doReq(client *http.Client, url string, t *testing.T) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// test server  ------------------------------------------------------------
const useFsStore = "fs"

func testServer(SessionDur, MaxSessionDur, update time.Duration, storeType string) (*httptest.Server, *http.Client) {
	var store sessions.Store
	if storeType == useFsStore {
		store, _ = sessionauth.NewFsStore("", securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	}

	authSess, err := sessionauth.NewAuthMngr(sessionauth.Cfg{
		Store:         store,
		SessionDur:    SessionDur,
		MaxSessionDur: MaxSessionDur,
		MinWriteSpace: update,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.RequestURI == "/login" {
			err = authSess.Login(r, w, "tester")
			if err != nil {
				spew.Dump(err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "ok", http.StatusOK)
		} else if r.RequestURI == "/form-login" {
			user := dummyUser{}
			handler := sessionauth.FormAuthHandler(authSess, user)
			handler.ServeHTTP(w, r)
		} else if r.RequestURI == "/json-login" {
			user := dummyUser{}
			handler := sessionauth.JsonAuthHandler(authSess, user)
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

// dummyUser  ------------------------------------------------------------

type dummyUser struct {
	user string
	pass string
}

func (st dummyUser) AllowLogin(user string, hash string) bool {
	if st.user == "" {
		st.user = "admin"
	}
	if st.pass == "" {
		st.pass = "admin"
	}
	if user == st.user && hash == st.pass {
		return true
	}
	return false
}
