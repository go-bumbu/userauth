package cookieauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/gorilla/securecookie"
)

func ExampleManager_Middleware() {
	protectedSite := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "protected")
	})

	store, _ := cookieauth.NewFsStore("", securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	cookieAuth, _ := cookieauth.New(cookieauth.Cfg{
		Store:         store,
		SessionDur:    time.Hour,
		MaxSessionDur: 24 * time.Hour,
		MinWriteSpace: 2 * time.Minute,
	})

	loginReq, _ := http.NewRequest(http.MethodGet, "", nil)
	loginRespRec := httptest.NewRecorder()
	_ = cookieAuth.LoginUser(loginReq, loginRespRec, "demo", true)

	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	loginResp := http.Response{Header: loginRespRec.Header()}
	req.Header.Set("Cookie", loginResp.Cookies()[0].String())

	protectedHandler := cookieAuth.Middleware(protectedSite)
	respRec2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(respRec2, req)
	resp := respRec2.Result()
	fmt.Println(resp.StatusCode)
	// Output: 200
}
