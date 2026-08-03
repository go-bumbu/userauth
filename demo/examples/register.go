package examples

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/register"
	registerhandlers "github.com/go-bumbu/userauth/register/handlers"
	pendingmemory "github.com/go-bumbu/userauth/register/pendingstore/memory"
	"github.com/go-bumbu/userauth/userstore/userdb"
	csmemory "github.com/go-bumbu/userauth/codestore/memory"
)

// Register handles user self-registration (password-based and
// email-verified). The demo owns only the transport — forms, redirects,
// rendering; the registration rules (login availability, pending state,
// email verification, single creation point) live in register.Flow.
type Register struct {
	log   *slog.Logger
	rnd   *web.Renderer
	open  *register.Flow // username+password, no checks
	email *register.Flow // email + password, email verification check
	board *registerCodeBoard
}

// userdbCreator adapts userdb.Store to register.UserCreator: the flow hands
// over a bcrypt hash, which the store persists as-is.
type userdbCreator struct {
	users *userdb.Store
}

func (c userdbCreator) CreateVerifiedUser(u register.NewUser) error {
	return c.users.CreateUserWithHashedPassword(userdb.User{
		LoginID:              u.LoginID,
		Pw:                   u.PasswordHash,
		Enabled:              true,
		PrimaryEmail:         u.Email,
		PrimaryEmailVerified: u.EmailVerified,
	})
}

// NewRegister wires both registration flows over the shared DB user store.
func NewRegister(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) *Register {
	creator := userdbCreator{users: users}
	board := newRegisterCodeBoard()
	codes := userauth.NewVerificationCodeService(csmemory.New(), userauth.VerificationCodeOpts{
		CodeLength: 6,
		Expiry:     10 * time.Minute,
	})
	return &Register{
		log:   log,
		rnd:   rnd,
		board: board,
		open: &register.Flow{
			Users:   users,
			Creator: creator,
			Logger:  log,
		},
		email: &register.Flow{
			Users:   users,
			Creator: creator,
			Checks: []register.Check{
				// a real deployment would wire an SMTP deliverer instead of the board
				register.EmailCheck{Codes: codes, Deliver: board},
			},
			Pending:        pendingmemory.New(),
			UsernameFormat: userauth.UsernameFormatEmail,
			Logger:         log,
		},
	}
}

// Password handles GET/POST /register (username+password registration).
func (a *Register) Password(w http.ResponseWriter, r *http.Request) {
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

	_, err := a.open.Start(r, w, register.StartInput{LoginID: login, Password: password})
	if err != nil {
		renderErr(registerErrMsg(err))
		return
	}

	a.rnd.Render(w, r, "register.tmpl.html", map[string]any{
		"Success": "User \"" + login + "\" registered successfully.",
	})
}

// Email handles GET/POST /register/email (email + password; the flow issues
// a verification code and parks the registration until it is confirmed).
func (a *Register) Email(w http.ResponseWriter, r *http.Request) {
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

	res, err := a.email.Start(r, w, register.StartInput{LoginID: email, Password: password})
	if err != nil {
		renderErr(registerErrMsg(err))
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
func (a *Register) EmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		data := map[string]any{"Email": email}
		if code, ok := a.board.lookup(email); ok {
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

	res, err := a.email.VerifyCheck(r, w, email, register.CheckEmail, code)
	if err != nil {
		renderErr(registerErrMsg(err))
		return
	}
	if !res.Done {
		renderErr("Invalid or expired verification code.")
		return
	}
	a.board.clear(email)

	a.rnd.Render(w, r, "register_email_verify.tmpl.html", map[string]any{
		"Email":   email,
		"Success": "Account created. You can now log in at /profile/login.",
	})
}

// registerErrMsg maps flow errors to user-facing messages: taken usernames
// and validation failures are meant to be shown; anything else is internal.
func registerErrMsg(err error) string {
	if errors.Is(err, register.ErrUserExists) {
		return "This username is already taken."
	}
	var vErr *register.ValidationError
	if errors.As(err, &vErr) {
		return vErr.Msg
	}
	return "Internal error, please try again."
}

// RegisterAPI exposes the same email-verified registration as a JSON API
// using the register/handlers preset — the transport SPAs would consume.
// The demo cannot send email, so the deliverer logs the code to the server
// console instead.
func RegisterAPI(log *slog.Logger, users *userdb.Store) *registerhandlers.JSON {
	return registerhandlers.New(registerhandlers.Cfg{
		Users:   users,
		Creator: userdbCreator{users: users},
		Pending: pendingmemory.New(),
		Codes: userauth.NewVerificationCodeService(csmemory.New(), userauth.VerificationCodeOpts{
			CodeLength: 6,
			Expiry:     10 * time.Minute,
		}),
		Deliver:        logDeliverer{log: log},
		UsernameFormat: userauth.UsernameFormatEmail,
		Logger:         log,
	})
}

// logDeliverer prints the verification code to the server log; a real
// deployment would wire delivery/smtp instead.
type logDeliverer struct {
	log *slog.Logger
}

func (d logDeliverer) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	d.log.Info("register api: verification code issued", "to", to, "code", code)
	return nil
}

// registerCodeBoard is the demo's userauth.Deliverer: instead of emailing
// the code it remembers the latest plaintext code per email so the verify
// page can display it. The verification store only keeps a hash, so this is
// the only place the plaintext survives.
type registerCodeBoard struct {
	mu    sync.Mutex
	codes map[string]string
}

func newRegisterCodeBoard() *registerCodeBoard {
	return &registerCodeBoard{codes: make(map[string]string)}
}

// Deliver implements userauth.Deliverer by stashing the code for display.
func (b *registerCodeBoard) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes[to] = code
	return nil
}

func (b *registerCodeBoard) lookup(email string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	code, ok := b.codes[email]
	return code, ok
}

func (b *registerCodeBoard) clear(email string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.codes, email)
}
