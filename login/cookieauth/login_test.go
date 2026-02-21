package cookieauth_test

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/authhandler/cookieauth"
	loginhandler "github.com/go-bumbu/userauth/login/cookieauth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type dummyUser struct{}

func (dummyUser) GetUser(id string) (userauth.User, error) {
	return userauth.User{
		Id:      "admin",
		HashPw:  userauth.MustHashPw("admin"),
		Enabled: true,
	}, nil
}

const useFsStore = "fs"
const useCookieStore = "cookie"

var sessionStores = []string{useFsStore, useCookieStore}

func testServer(sessionDur, maxSessionDur, update time.Duration, allowRenew bool, storeType string) (*httptest.Server, *http.Client) {
	var store sessions.Store
	switch storeType {
	case useFsStore:
		store, _ = cookieauth.NewFsStore("", securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	case useCookieStore:
		store, _ = cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	default:
		panic("session store type not defined")
	}

	authSess, err := cookieauth.New(cookieauth.Cfg{
		Store:         store,
		SessionDur:    sessionDur,
		AllowRenew:    allowRenew,
		MaxSessionDur: maxSessionDur,
		MinWriteSpace: update,
	})
	if err != nil {
		panic(err)
	}

	auth := userauth.NewLoginHandler(dummyUser{}, nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/login":
			if err := authSess.LoginUser(r, w, "tester", true); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/form-login":
			loginhandler.FormAuthHandler(authSess, auth, "").ServeHTTP(w, r)
		case "/json-login":
			loginhandler.JsonAuthHandler(authSess, auth).ServeHTTP(w, r)
		default:
			authSess.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(w, r)
		}
	})

	svr := httptest.NewTLSServer(handler)
	jar, _ := cookiejar.New(nil)
	c := svr.Client()
	c.Jar = jar
	return svr, c
}

func doReq(client *http.Client, url string, t *testing.T) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
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

// TestProcessSessionData tests SessionData.Verify() from authhandler/cookieauth (session validity and force re-auth).
func TestProcessSessionData(t *testing.T) {
	tcs := []struct {
		name string
		in   cookieauth.SessionData
		want cookieauth.SessionData
	}{
		{
			name: "session valid",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("10m"), ForceReAuth: getTime("1m"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: true}},
		},
		{
			name: "session expired",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("-1s"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: false}},
		},
		{
			name: "session NOT expired, but hard logout",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("10m"), ForceReAuth: getTime("-1s"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: false}},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in
			got.Verify()
			want := tc.want
			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(cookieauth.SessionData{}, "Expiration", "ForceReAuth")); diff != "" {
				t.Errorf("Content mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestJsonAuthHandler(t *testing.T) {
	tcs := []struct {
		name     string
		password string
		expect   int
	}{
		{name: "valid login", password: "admin", expect: 200},
		{name: "invalid login", password: "nope", expect: 401},
	}
	for _, storeType := range sessionStores {
		t.Run(storeType, func(t *testing.T) {
			t.Parallel()
			for _, tc := range tcs {
				t.Run(tc.name, func(t *testing.T) {
					svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, false, storeType)
					defer svr.Close()
					jsonStr := []byte(`{"username":"admin","password":"` + tc.password + `"}`)
					req, err := http.NewRequest("POST", svr.URL+"/json-login", bytes.NewBuffer(jsonStr))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != tc.expect {
						t.Errorf("expected status %d, got %d", tc.expect, resp.StatusCode)
					}
				})
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
		{name: "valid login", password: "admin", expect: 200},
		{name: "invalid login", password: "nope", expect: 401},
	}
	for _, storeType := range sessionStores {
		t.Run(storeType, func(t *testing.T) {
			t.Parallel()
			for _, tc := range tcs {
				t.Run(tc.name, func(t *testing.T) {
					svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, false, storeType)
					defer svr.Close()
					param := url.Values{}
					param.Set("username", "admin")
					param.Set("password", tc.password)
					req, err := http.NewRequest("POST", svr.URL+"/form-login", bytes.NewBufferString(param.Encode()))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != tc.expect {
						t.Errorf("expected status %d, got %d", tc.expect, resp.StatusCode)
					}
				})
			}
		})
	}
}

func TestSessionManagement(t *testing.T) {
	for _, storeType := range sessionStores {
		t.Run(storeType, func(t *testing.T) {
			t.Parallel()

			t.Run("access resource after login", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 200*time.Millisecond, 0, false, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("first request: expected 401, got %d", resp.StatusCode)
				}
				resp = doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Errorf("login: expected 200, got %d", resp.StatusCode)
				}
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusOK {
					t.Errorf("after login: expected 200, got %d", resp.StatusCode)
				}
			})

			t.Run("401 after session expired", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 500*time.Millisecond, 0, false, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Errorf("login: expected 200, got %d", resp.StatusCode)
				}
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusOK {
					t.Errorf("first request: expected 200, got %d", resp.StatusCode)
				}
				time.Sleep(100 * time.Millisecond)
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("after expiry: expected 401, got %d", resp.StatusCode)
				}
			})

			t.Run("renew session", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 2000*time.Millisecond, 1*time.Millisecond, true, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("login: expected 200, got %d", resp.StatusCode)
				}
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusOK {
					t.Errorf("expected 200, got %d", resp.StatusCode)
				}
			})

			t.Run("don't allow session renew", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 2000*time.Millisecond, 1*time.Millisecond, false, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("login: expected 200, got %d", resp.StatusCode)
				}
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("expected 401, got %d", resp.StatusCode)
				}
			})

			t.Run("401 after max session duration", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 60*time.Millisecond, 0, false, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("login: expected 200, got %d", resp.StatusCode)
				}
				for i := 0; i < 4; i++ {
					time.Sleep(20 * time.Millisecond)
					doReq(c, svr.URL+"/something", t)
				}
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("expected 401, got %d", resp.StatusCode)
				}
			})

			t.Run("401 forced session to not be updated", func(t *testing.T) {
				svr, c := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, false, storeType)
				defer svr.Close()
				resp := doReq(c, svr.URL+"/login", t)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("login: expected 200, got %d", resp.StatusCode)
				}
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				doReq(c, svr.URL+"/something", t)
				time.Sleep(20 * time.Millisecond)
				resp = doReq(c, svr.URL+"/something", t)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("expected 401, got %d", resp.StatusCode)
				}
			})
		})
	}
}
