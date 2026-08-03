// Package register holds the demo examples for user self-registration built
// on flow/register: an HTML form flow (username+password and email-verified)
// and the same email-verified flow as a JSON API.
package register

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/internal/deliver"
	"github.com/go-bumbu/userauth/demo/web"
	regflow "github.com/go-bumbu/userauth/flow/register"
	pendingmemory "github.com/go-bumbu/userauth/flow/register/pendingstore/memory"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/userstore/userdb"
)

// Forms handles user self-registration (password-based and email-verified).
// The demo owns only the transport — forms, redirects, rendering; the
// registration rules (login availability, pending state, email verification,
// single creation point) live in regflow.Flow.
type Forms struct {
	log   *slog.Logger
	rnd   *web.Renderer
	open  *regflow.Flow // username+password, no checks
	email *regflow.Flow // email + password, email verification check
	board *deliver.Board
}

// userdbCreator adapts userdb.Store to regflow.UserCreator: the flow hands
// over a bcrypt hash, which the store persists as-is.
type userdbCreator struct {
	users *userdb.Store
}

func (c userdbCreator) CreateVerifiedUser(u regflow.NewUser) error {
	return c.users.CreateUserWithHashedPassword(userdb.User{
		LoginID:              u.LoginID,
		Pw:                   u.PasswordHash,
		Enabled:              true,
		PrimaryEmail:         u.Email,
		PrimaryEmailVerified: u.EmailVerified,
	})
}

// NewForms wires both registration flows over the shared DB user store.
func NewForms(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) *Forms {
	creator := userdbCreator{users: users}
	board := deliver.NewBoard()
	codes := verificationcode.NewService(csmemory.New(), verificationcode.Opts{
		CodeLength: 6,
		Expiry:     10 * time.Minute,
	})
	return &Forms{
		log:   log,
		rnd:   rnd,
		board: board,
		open: &regflow.Flow{
			Users:   users,
			Creator: creator,
			Logger:  log,
		},
		email: &regflow.Flow{
			Users:   users,
			Creator: creator,
			Checks: []regflow.Check{
				// a real deployment would wire an SMTP deliverer instead of the board
				regflow.EmailCheck{Codes: codes, Deliver: board},
			},
			Pending:        pendingmemory.New(),
			UsernameFormat: userauth.UsernameFormatEmail,
			Logger:         log,
		},
	}
}

// Password handles GET/POST /register (username+password registration).
func (a *Forms) Password(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.rnd.Render(w, r, "register.tmpl.html", nil)
		return
	}

	login := strings.TrimSpace(r.FormValue("login"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	renderErr := func(msg string) {
		a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
			"Error": msg,
			"Login": login,
		})
	}

	if password != confirm {
		renderErr("Passwords do not match.")
		return
	}

	_, err := a.open.Start(r, w, regflow.StartInput{LoginID: login, Password: password})
	if err != nil {
		renderErr(errMsg(err))
		return
	}

	a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
		"Success": "User \"" + login + "\" registered successfully.",
	})
}

// Email handles GET/POST /register/email (email + password; the flow issues
// a verification code and parks the registration until it is confirmed).
func (a *Forms) Email(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.rnd.Render(w, r, "register_email.tmpl.html", nil)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	renderErr := func(msg string) {
		a.rnd.Render(w, r, "register_email.tmpl.html", map[string]any{
			"Error": msg,
			"Email": email,
		})
	}

	if password != confirm {
		renderErr("Passwords do not match.")
		return
	}

	res, err := a.email.Start(r, w, regflow.StartInput{LoginID: email, Password: password})
	if err != nil {
		renderErr(errMsg(err))
		return
	}
	if !res.OK {
		renderErr("Registration was rejected.")
		return
	}

	http.Redirect(w, r, "/register/email/verify?email="+email, http.StatusSeeOther)
}

// EmailVerify handles GET/POST /register/email/verify (validates the code;
// the flow creates the account when it matches).
func (a *Forms) EmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		data := map[string]any{"Email": email}
		if code, ok := a.board.Lookup(email); ok {
			data["PlainCode"] = code
		}
		a.rnd.Render(w, r, "register_email_verify.tmpl.html", data)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))

	renderErr := func(msg string) {
		a.rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
			"Email": email,
			"Error": msg,
		})
	}

	res, err := a.email.VerifyCheck(r, w, email, regflow.CheckEmail, code)
	if err != nil {
		renderErr(errMsg(err))
		return
	}
	if !res.Done {
		renderErr("Invalid or expired verification code.")
		return
	}
	a.board.Clear(email)

	a.rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
		"Email":   email,
		"Success": "Account created. You can now log in at /profile/login.",
	})
}

// errMsg maps flow errors to user-facing messages: taken usernames and
// validation failures are meant to be shown; anything else is internal.
func errMsg(err error) string {
	if errors.Is(err, regflow.ErrUserExists) {
		return "This username is already taken."
	}
	var vErr *regflow.ValidationError
	if errors.As(err, &vErr) {
		return vErr.Msg
	}
	return "Internal error, please try again."
}
