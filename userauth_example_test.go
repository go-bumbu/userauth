package userauth_test

import (
	"fmt"
	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/staticusers"
)

func ExampleStaticUsers() {

	// define static UserGetter
	u := []staticusers.User{
		{
			Id:      "demo",
			HashPw:  userauth.MustHash("demo"),
			Enabled: false,
		},
		{
			Id:      "admin",
			HashPw:  userauth.MustHash("admin"),
			Enabled: true,
		},
	}

	// use static UserGetter as mock user provider,
	// UserGetter can also be loaded from files with static.FromFile("my-file.yaml|json")
	users := staticusers.Users{Users: u}

	// create a login handler that will check user login
	loginHandler := userauth.LoginHandler{
		UserStore: &users,
	}

	// check if the user demo (from file) can log in
	isOK, err := loginHandler.AllowLogin("admin", "admin")
	panicOnErr(err)
	fmt.Printf("user admin can login: %v\n", isOK)

	// check if the user demo can't log in since the account is disabled
	isOK, err = loginHandler.AllowLogin("demo", "demo")
	panicOnErr(err)
	fmt.Printf("user demo can login: %v", isOK)

	// Output:
	// user admin can login: true
	// user demo can login: false
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
