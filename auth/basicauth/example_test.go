package basicauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/go-bumbu/userauth/auth/basicauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
)

func Example_basicauth_Middleware() {
	protectedSite := dummyHandler()

	// create a user store; basicauth fetches and verifies user credentials from it
	users := dummyUser{
		user: "demo",
		pass: hashutil.MustHashPassword("demo"),
	}
	// create an instance of basic auth
	basicAuth := basicauth.NewHandler(users, "", true, nil)

	// use the middleware to protect the page
	protectedHandler := basicAuth.Middleware(protectedSite)

	// the client will make a request with credentials
	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	req.SetBasicAuth("demo", "demo")

	// check the response
	respRec := httptest.NewRecorder()
	protectedHandler.ServeHTTP(respRec, req)
	resp := respRec.Result()
	fmt.Println(resp.StatusCode)

	// Output: 200

}
