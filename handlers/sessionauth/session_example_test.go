package sessionauth_test

import (
	"fmt"
	"github.com/go-bumbu/userauth/handlers/sessionauth"
	"github.com/gorilla/securecookie"
	"net/http"
	"net/http/httptest"
	"time"
)

// nolint: govet
func ExampleSessionAuth() {

	// a handler for the auth protected content
	protectedSite := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "protected")
	})

	// create a session store:
	store, _ := sessionauth.NewFsStore("", securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	// create an instance of session auth
	sessionAuth, _ := sessionauth.New(sessionauth.Cfg{
		Store:         store,
		SessionDur:    time.Hour,       // time the user is logged in
		MaxSessionDur: 24 * time.Hour,  // time after the user is forced to re-login anyway
		MinWriteSpace: 2 * time.Minute, // throttle write operations on the session
	})

	// make a call to the loging handler
	loginReq, _ := http.NewRequest(http.MethodGet, "", nil)
	loginRespRec := httptest.NewRecorder()
	_ = sessionAuth.LoginUser(loginReq, loginRespRec, "demo")

	// the client will make a request with an authenticated session
	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	// copy the session cookie from the login Request into the new request
	// normally the browser/client takes care of this
	loginResp := http.Response{Header: loginRespRec.Header()}
	req.Header.Set("Cookie", loginResp.Cookies()[0].String())

	// use the middleware to protect the page
	protectedHandler := sessionAuth.Middleware(protectedSite)

	// check the response
	respRec2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(respRec2, req)
	resp := respRec2.Result()
	fmt.Println(resp.StatusCode)

	// Output: 200
}
