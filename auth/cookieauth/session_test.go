package cookieauth_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/login":
			if err := authSess.LoginUser(r, w, "tester", true); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
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
