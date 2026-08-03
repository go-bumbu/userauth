package register_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/register"
	"github.com/go-bumbu/userauth/register/invite"
	invitememory "github.com/go-bumbu/userauth/register/invite/memory"
	"github.com/go-bumbu/userauth/register/pendingstore/memory"
	csmemory "github.com/go-bumbu/userauth/codestore/memory"
)

// exampleUsers is an empty user store; a real application would use
// userstore/userdb, which satisfies userauth.UserGetter.
type exampleUsers struct{}

func (exampleUsers) GetUser(string) (userauth.User, error) {
	return userauth.User{}, userauth.ErrUserNotFound
}

// exampleCreator stands in for the final user store write; a real
// application adapts userdb.Store.CreateUserWithHashedPassword.
type exampleCreator struct{}

func (exampleCreator) CreateVerifiedUser(u register.NewUser) error {
	fmt.Printf("user created: %s (email verified: %v)\n", u.LoginID, u.EmailVerified)
	return nil
}

// exampleDeliverer stands in for an SMTP deliverer: it hands the code back
// to the example instead of sending it.
type exampleDeliverer struct {
	lastCode string
}

func (d *exampleDeliverer) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	d.lastCode = code
	fmt.Printf("code delivered to %s\n", to)
	return nil
}

// Example shows open registration: no checks, the account is created on the
// first submission.
func Example() {
	flow := &register.Flow{
		Users:   exampleUsers{},
		Creator: exampleCreator{},
	}

	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()

	res, _ := flow.Start(r, w, register.StartInput{LoginID: "bob", Password: "secret"})
	fmt.Printf("open registration: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// user created: bob (email verified: false)
	// open registration: ok=true done=true
}

// Example_emailVerification requires proving control of the email address:
// Start persists a pending registration and delivers a one-time code, and
// the account is only created when the code comes back.
func Example_emailVerification() {
	codes := userauth.NewVerificationCodeService(csmemory.New(), userauth.VerificationCodeOpts{})
	mail := &exampleDeliverer{}

	flow := &register.Flow{
		Users:          exampleUsers{},
		Creator:        exampleCreator{},
		Checks:         []register.Check{register.EmailCheck{Codes: codes, Deliver: mail}},
		Pending:        memory.New(),
		UsernameFormat: userauth.UsernameFormatEmail,
	}

	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()

	res, _ := flow.Start(r, w, register.StartInput{LoginID: "alice@example.com", Password: "secret"})
	fmt.Printf("after start: ok=%v done=%v next=%v\n", res.OK, res.Done, res.Next)

	res, _ = flow.VerifyCheck(r, w, "alice@example.com", register.CheckEmail, mail.lastCode)
	fmt.Printf("after code: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// code delivered to alice@example.com
	// after start: ok=true done=false next=[email]
	// user created: alice@example.com (email verified: true)
	// after code: ok=true done=true
}

// Example_inviteOnly gates registration behind an invite code issued by an
// admin. The invite is validated at Start and consumed atomically when the
// account is created.
func Example_inviteOnly() {
	invites := invite.New(invitememory.New(), invite.Opts{})
	inv, _ := invites.Issue(invite.IssueOpts{Note: "for bob"})

	flow := &register.Flow{
		Users:   exampleUsers{},
		Creator: exampleCreator{},
		Checks:  []register.Check{register.InviteCheck{Invites: invites}},
	}

	r := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()

	res, _ := flow.Start(r, w, register.StartInput{LoginID: "bob", Password: "secret", InviteCode: "wrong"})
	fmt.Printf("bad invite: ok=%v\n", res.OK)

	res, _ = flow.Start(r, w, register.StartInput{LoginID: "bob", Password: "secret", InviteCode: inv.Code})
	fmt.Printf("good invite: ok=%v done=%v\n", res.OK, res.Done)

	// Output:
	// bad invite: ok=false
	// user created: bob (email verified: false)
	// good invite: ok=true done=true
}
