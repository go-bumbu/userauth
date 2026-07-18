package loginflow_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/loginflow"
	"github.com/go-bumbu/userauth/loginflow/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	vcmemory "github.com/go-bumbu/userauth/verificationcode/memory"
	"github.com/pquerna/otp/totp"
)

// printDeliverer stands in for an SMTP/SMS deliverer: it hands the code back
// to the example instead of sending it.
type printDeliverer struct {
	lastCode string
}

func (d *printDeliverer) Deliver(_ context.Context, _ string, code string, _ time.Time) error {
	d.lastCode = code
	return nil
}

// noopSession stands in for a real session manager (e.g. cookieauth.Manager,
// which satisfies loginflow.UserLogin implicitly).
type noopSession struct{}

func (noopSession) LoginUser(_ *http.Request, _ http.ResponseWriter, userID string, _ bool) error {
	fmt.Printf("session created for %s\n", userID)
	return nil
}

// Example shows the minimal wiring: a password-only policy over a static user
// store. The engine rejects bad credentials with a zero Result and creates
// the session exactly once, when the policy is satisfied.
func Example() {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "bob", HashPw: userauth.MustHashPw("secret"), Enabled: true},
	}}

	flow := &loginflow.Flow{
		Users:    users,
		Methods:  []loginflow.Method{loginflow.PasswordMethod{Users: users}},
		Policy:   loginflow.RequireAny(loginflow.Chain{loginflow.MethodPassword}),
		Attempts: memory.New(),
		Session:  noopSession{},
	}

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	w := httptest.NewRecorder()

	res, _ := flow.Submit(r, w, "bob", loginflow.MethodPassword, "wrong", false)
	fmt.Printf("wrong password: ok=%v done=%v\n", res.OK, res.Done)

	res, _ = flow.Submit(r, w, "bob", loginflow.MethodPassword, "secret", false)
	fmt.Printf("right password: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// wrong password: ok=false done=false
	// session created for bob
	// right password: ok=true done=true
}

// Example_emailPlusTOTP composes a passwordless email code with TOTP as a
// mandatory second factor — a flow the fixed handlers cannot express, written
// here as one line of policy.
func Example_emailPlusTOTP() {
	const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "alice@example.com", Enabled: true, TOTPSecret: totpSecret},
	}}
	codes := userauth.NewVerificationCodeService(vcmemory.New(), userauth.VerificationCodeOpts{})
	mail := &printDeliverer{}

	flow := &loginflow.Flow{
		Users: users,
		Methods: []loginflow.Method{
			loginflow.EmailCodeMethod(codes, mail),
			loginflow.TOTPMethod{TOTP: users},
		},
		Policy:   loginflow.RequireAny(loginflow.Chain{loginflow.MethodEmail, loginflow.MethodTOTP}),
		Attempts: memory.New(),
		Session:  noopSession{},
	}

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	w := httptest.NewRecorder()

	// Step 1: issue and "deliver" a one-time code. For unknown or disabled
	// users this silently does nothing, so the endpoint stays enumeration-safe.
	_ = flow.Initiate(r, "alice@example.com", loginflow.MethodEmail)

	// Step 2: the user submits the emailed code. Result.Next tells the
	// transport which factors may come next.
	res, _ := flow.Submit(r, w, "alice@example.com", loginflow.MethodEmail, mail.lastCode, false)
	fmt.Printf("after email code: ok=%v done=%v next=%v\n", res.OK, res.Done, res.Next)

	// Step 3: the user submits their authenticator code; the policy is now
	// satisfied and the session is created.
	code, _ := totp.GenerateCode(totpSecret, time.Now())
	res, _ = flow.Submit(r, w, "alice@example.com", loginflow.MethodTOTP, code, false)
	fmt.Printf("after totp: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// after email code: ok=true done=false next=[totp]
	// session created for alice@example.com
	// after totp: ok=true done=true
}

// Example_alternativeChains lets the user choose between password+TOTP and a
// plain email-code login: RequireAny is satisfied by whichever chain
// completes first.
func Example_alternativeChains() {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "bob", HashPw: userauth.MustHashPw("secret"), Enabled: true},
	}}
	codes := userauth.NewVerificationCodeService(vcmemory.New(), userauth.VerificationCodeOpts{})
	mail := &printDeliverer{}

	flow := &loginflow.Flow{
		Users: users,
		Methods: []loginflow.Method{
			loginflow.PasswordMethod{Users: users},
			loginflow.TOTPMethod{TOTP: users},
			loginflow.EmailCodeMethod(codes, mail),
		},
		Policy: loginflow.RequireAny(
			loginflow.Chain{loginflow.MethodPassword, loginflow.MethodTOTP},
			loginflow.Chain{loginflow.MethodEmail},
		),
		Attempts: memory.New(),
		Session:  noopSession{},
	}

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	w := httptest.NewRecorder()

	// bob picks the email chain; one factor completes the login.
	_ = flow.Initiate(r, "bob", loginflow.MethodEmail)
	res, _ := flow.Submit(r, w, "bob", loginflow.MethodEmail, mail.lastCode, false)
	fmt.Printf("email chain: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// session created for bob
	// email chain: ok=true done=true
}

// ExampleSecondFactorAfter reproduces the classic CanLogin behavior: password
// is enough, unless the user has second factors enrolled — then one of them
// is additionally required. Enrollment is read per user from the
// SecondFactorProvider, so the same policy serves both kinds of users.
func ExampleSecondFactorAfter() {
	const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "plain", HashPw: userauth.MustHashPw("secret"), Enabled: true},
		{Id: "careful", HashPw: userauth.MustHashPw("secret"), Enabled: true, TOTPSecret: totpSecret},
	}}

	flow := &loginflow.Flow{
		Users: users,
		Methods: []loginflow.Method{
			loginflow.PasswordMethod{Users: users},
			loginflow.TOTPMethod{TOTP: users},
		},
		// staticusers.Users implements userauth.SecondFactorProvider.
		Policy:   loginflow.SecondFactorAfter(loginflow.MethodPassword, users),
		Attempts: memory.New(),
		Session:  noopSession{},
	}

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	w := httptest.NewRecorder()

	res, _ := flow.Submit(r, w, "plain", loginflow.MethodPassword, "secret", false)
	fmt.Printf("plain: done=%v\n", res.Done)

	res, _ = flow.Submit(r, w, "careful", loginflow.MethodPassword, "secret", false)
	fmt.Printf("careful: done=%v next=%v\n", res.Done, res.Next)

	// Output:
	// session created for plain
	// plain: done=true
	// careful: done=false next=[totp]
}
