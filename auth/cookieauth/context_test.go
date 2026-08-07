package cookieauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/google/go-cmp/cmp"
)

func TestCtxGetUserData(t *testing.T) {
	t.Run("returns user data set on the request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		want := cookieauth.UserData{UserId: "tester", IsAuthenticated: true}
		cookieauth.CtxSetUserData(req, cookieauth.SessionData{UserData: want})

		got, err := cookieauth.CtxGetUserData(req)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Content mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("error when no user data in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, err := cookieauth.CtxGetUserData(req)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("error when userid is empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		cookieauth.CtxSetUserData(req, cookieauth.SessionData{
			UserData: cookieauth.UserData{IsAuthenticated: true},
		})
		_, err := cookieauth.CtxGetUserData(req)
		if err == nil {
			t.Fatal("expected an error on empty userid, got nil")
		}
	})
}
