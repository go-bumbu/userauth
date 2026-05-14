package userauth_test

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/pquerna/otp/totp"
)

func Example_usrauth_CanLogin() {

	// define static UserGetter
	u := []staticusers.User{
		{
			Id:      "demo",
			HashPw:  userauth.MustHashPw("demo"),
			Enabled: false,
		},
		{
			Id:      "admin",
			HashPw:  userauth.MustHashPw("admin"),
			Enabled: true,
		},
	}

	// use static UserGetter as mock user provider,
	// UserGetter can also be loaded from files with static.FromFile("my-file.yaml|json")
	users := staticusers.Users{Users: u}

	// create a login handler that will check user login
	loginHandler := userauth.LoginHandler{UserStore: &users}

	// check if the user demo (from file) can log in
	result, _ := loginHandler.CanLogin("admin", "admin")
	fmt.Printf("user admin can login: %v\n", result.Authenticated)

	// check if the user demo can't log in since the account is disabled
	result, err := loginHandler.CanLogin("demo", "demo")
	switch {
	case errors.Is(err, userauth.ErrUserNotFound), errors.Is(err, userauth.ErrUserDisabled):
		// expected errors
	default:
		panicOnErr(err)
	}
	fmt.Printf("user demo can login: %v", result.Authenticated)

	// Output:
	// user admin can login: true
	// user demo can login: false
}

func Example_usrauth_TOTP() {
	// Static user store with TOTP defined per user (hardcoded here; same fields can be in YAML/JSON).
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- example TOTP secret
	users := &staticusers.Users{
		Users: []staticusers.User{{
			Id:         "totpuser",
			HashPw:     userauth.MustHashPw("password"),
			Enabled:    true,
			TOTPSecret: secret,
		}},
	}

	lh := userauth.LoginHandler{
		UserStore:     users,
		SecondFactors: users,
		TOTP:          users,
	}

	// Step 1: password-only login returns Requires2FA and available factors
	result, err := lh.CanLogin("totpuser", "password")
	panicOnErr(err)
	fmt.Printf("Requires2FA: %v\n", result.Requires2FA)
	fmt.Printf("Available: %v\n", result.AvailableSecondFactors)

	// Step 2: generate current TOTP code and verify
	code, err := totp.GenerateCode(secret, time.Now())
	panicOnErr(err)
	result, err = lh.VerifyTOTP("totpuser", code)
	panicOnErr(err)
	fmt.Printf("TOTP verified: %v\n", result.Authenticated)

	// Wrong code does not authenticate
	result, _ = lh.VerifyTOTP("totpuser", "000000")
	fmt.Printf("Wrong code verified: %v\n", result.Authenticated)

	// Output:
	// Requires2FA: true
	// Available: [totp]
	// TOTP verified: true
	// Wrong code verified: false
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
