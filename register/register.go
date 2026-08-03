// Package register is a composable self-registration engine: a pending
// registration accumulates verified checks (email verification, invite
// code, …) until all of them are satisfied, and only then is the account
// created.
//
// It is the registration counterpart of loginflow, sharing its philosophy —
// transport-agnostic core, pluggable requirements, uniform failure results —
// but deliberately simpler: registration needs no policy combinatorics, so a
// flat list of required checks replaces loginflow's Policy. Invariants:
//
//   - pending registrations expire (DefaultPendingExpiry)
//   - the account is created in exactly one place, after every check passed
//   - the pending record only ever holds the bcrypt password hash, never the
//     plaintext password
//   - credential-shaped failures (wrong code, expired or missing pending
//     registration, invalid invite) produce the same Result{OK:false}, so
//     transports stay uniform; errors are reserved for internal failures
//
// Unlike login, registration is deliberately not enumeration-safe about
// existing usernames: Start returns ErrUserExists so transports can render
// "username taken" — a registration form that pretends to accept a taken
// username is hostile UX for negligible gain.
package register

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/support/hashutil"
)

// DefaultPendingExpiry bounds how long a pending registration stays valid.
// Registrations live longer than login attempts: the user may need to fetch
// an email.
const DefaultPendingExpiry = 30 * time.Minute

// Registration is the server-side state of a registration in progress. It
// holds everything needed to create the account once all checks pass.
//
// PassHash is a bcrypt hash — implementations never see the plaintext
// password. PendingStore implementations MUST still protect the record
// (server-side storage or a signed+encrypted client token): Satisfied is a
// claim about verified checks.
type Registration struct {
	LoginID    string
	PassHash   string   // bcrypt hash of the chosen password — never plaintext
	Email      string   // equals LoginID when the username format is email
	InviteCode string   // consumed at account creation; empty without invite check
	Satisfied  []string // check IDs verified so far
	ExpiresAt  time.Time
}

// PendingStore persists registrations between check submissions.
// Implementations key by Registration.LoginID.
type PendingStore interface {
	Set(r *http.Request, w http.ResponseWriter, reg Registration) error
	Get(r *http.Request, loginID string) (Registration, error)
	Clear(r *http.Request, w http.ResponseWriter, loginID string) error
}

// NewUser is the completed registration handed to the UserCreator.
type NewUser struct {
	LoginID       string
	PasswordHash  string // bcrypt hash from hashutil
	Email         string
	EmailVerified bool // true when the email check ran
}

// UserCreator creates the final account from a completed registration. The
// password arrives already bcrypt-hashed; userauth.UserRegistrar cannot be
// used here because it takes a plaintext password.
//
// Implementations may return ErrUserExists (wrapped) when the login ID was
// taken concurrently, so transports can render the conflict even at the
// verify step.
type UserCreator interface {
	CreateVerifiedUser(u NewUser) error
}

// SessionCreator logs the freshly created user in.
// auth/cookieauth.Manager satisfies this implicitly.
type SessionCreator interface {
	LoginUser(r *http.Request, w http.ResponseWriter, userID string, keepLoggedIn bool) error
}

// PasswordValidator rejects unacceptable passwords. The returned error
// message is shown to the user (transports render it as a 400).
type PasswordValidator interface {
	ValidatePassword(pw string) error
}

// PasswordValidatorFunc adapts a function to the PasswordValidator interface.
type PasswordValidatorFunc func(pw string) error

func (f PasswordValidatorFunc) ValidatePassword(pw string) error { return f(pw) }

// InviteConsumer validates and consumes invite codes. *invite.Service
// satisfies this. Validate is a read-only courtesy check at Start; Consume
// is the authoritative, atomic use at account creation.
type InviteConsumer interface {
	Validate(code, email string) (bool, error)
	Consume(code, email string) (bool, error)
}

// ErrUserExists reports that the login ID is already taken. Transports
// should render it as a conflict ("username taken") — registration is
// deliberately not enumeration-safe, see the package comment.
var ErrUserExists = errors.New("register: user already exists")

// ValidationError is a user-input rejection (password policy, login ID
// format, missing fields). Transports render Msg to the user as a 400.
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string { return e.Msg }

// Result is the outcome of a Start or VerifyCheck call.
//
// OK=false means the submission was rejected for a credential-shaped reason
// (wrong or expired code, no pending registration, invalid invite). The
// engine does not say which, so transports can render one uniform failure.
type Result struct {
	OK   bool     // the submission was accepted
	Done bool     // all checks passed; the account has been created
	Next []string // when OK && !Done: check IDs still pending
}

// StartInput is the first submission of a registration.
type StartInput struct {
	LoginID    string
	Password   string // plaintext; hashed by Start, never stored
	Email      string // defaults to LoginID when the username format is email
	InviteCode string
}

// Flow is the registration engine. Users and Creator are required.
//
// Pending may be nil when every configured check is pre-verified at Start
// (or there are no checks): no pending registration is ever persisted then.
// A round-trip check (email verification) with a nil Pending store fails
// with an error at the first incomplete submission.
type Flow struct {
	Users          userauth.UserGetter // required: login ID availability
	Creator        UserCreator         // required: creates the account
	Checks         []Check             // empty = open registration
	Pending        PendingStore        // required for round-trip checks
	Password       PasswordValidator   // optional; default requires non-empty
	UsernameFormat userauth.UsernameFormat
	Session        SessionCreator // optional: auto-login after creation
	Expiry         time.Duration  // pending lifetime; defaults to DefaultPendingExpiry
	Logger         *slog.Logger   // optional; defaults to slog.Default()
}

func (f *Flow) logger() *slog.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return slog.Default()
}

func (f *Flow) expiry() time.Duration {
	if f.Expiry > 0 {
		return f.Expiry
	}
	return DefaultPendingExpiry
}

func (f *Flow) check() error {
	if f.Users == nil || f.Creator == nil {
		return errors.New("register: Users and Creator are required")
	}
	return nil
}

func (f *Flow) checkByID(id string) Check {
	for _, c := range f.Checks {
		if c.ID() == id {
			return c
		}
	}
	return nil
}

func (f *Flow) validatePassword(pw string) error {
	if f.Password != nil {
		return f.Password.ValidatePassword(pw)
	}
	if pw == "" {
		return errors.New("password is required")
	}
	return nil
}

// remaining returns the IDs of configured checks not yet satisfied.
func (f *Flow) remaining(satisfied []string) []string {
	var out []string
	for _, c := range f.Checks {
		if !contains(satisfied, c.ID()) {
			out = append(out, c.ID())
		}
	}
	return out
}

// userExists reports whether the login ID is taken. A non-nil error is an
// internal store failure.
func (f *Flow) userExists(loginID string) (bool, error) {
	_, err := f.Users.GetUser(loginID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, userauth.ErrUserNotFound) {
		return false, nil
	}
	return false, err
}

// validateStart normalizes and validates the start input: login ID presence
// and format (defaulting the email from an email-shaped login ID), login
// availability, and the password policy.
func (f *Flow) validateStart(in *StartInput) error {
	in.LoginID = strings.TrimSpace(in.LoginID)
	if in.LoginID == "" {
		return &ValidationError{Msg: "login is required"}
	}
	if err := userauth.ValidateLoginID(in.LoginID, f.UsernameFormat); err != nil {
		return &ValidationError{Msg: err.Error()}
	}
	if f.UsernameFormat == userauth.UsernameFormatEmail && in.Email == "" {
		in.Email = in.LoginID
	}
	if in.Email == "" && f.checkByID(CheckEmail) != nil {
		return &ValidationError{Msg: "email is required"}
	}

	exists, err := f.userExists(in.LoginID)
	if err != nil {
		return err
	}
	if exists {
		return ErrUserExists
	}

	if err := f.validatePassword(in.Password); err != nil {
		return &ValidationError{Msg: err.Error()}
	}
	return nil
}

// Start begins a registration: it validates the login ID and password, runs
// every pre-verifiable check against the input, and either creates the
// account (all checks satisfied) or persists a pending registration and
// initiates the round-trip checks (e.g. sends the email code).
//
// Starting again for the same login ID overwrites the previous pending
// registration: fresh password hash, fresh expiry, checks reset. This
// prevents a stranger from parking someone's username in pending state.
//
// Error shapes: ErrUserExists for a taken login ID, *ValidationError for
// rejected input (both user-facing); any other non-nil error is an internal
// failure. Credential-shaped rejections (invalid invite) come back as
// (Result{OK: false}, nil).
func (f *Flow) Start(r *http.Request, w http.ResponseWriter, in StartInput) (Result, error) {
	if err := f.check(); err != nil {
		return Result{}, err
	}
	if err := f.validateStart(&in); err != nil {
		return Result{}, err
	}

	// Pre-verifiable checks (e.g. invite code) run against the input itself;
	// any failure is credential-shaped and rejected uniformly.
	var satisfied []string
	for _, c := range f.Checks {
		pre, isPre := c.(PreVerifier)
		if !isPre {
			continue
		}
		ok, err := pre.PreVerify(in)
		if err != nil {
			return Result{}, fmt.Errorf("register: pre-verify %s: %w", c.ID(), err)
		}
		if !ok {
			f.logger().Debug("register: pre-verification failed", "loginID", in.LoginID, "check", c.ID())
			return Result{}, nil
		}
		satisfied = append(satisfied, c.ID())
	}

	hash, err := hashutil.HashPassword(in.Password)
	if err != nil {
		return Result{}, fmt.Errorf("register: hash password: %w", err)
	}
	reg := Registration{
		LoginID:    in.LoginID,
		PassHash:   hash,
		Email:      in.Email,
		InviteCode: in.InviteCode,
		Satisfied:  satisfied,
		ExpiresAt:  time.Now().Add(f.expiry()),
	}

	next := f.remaining(reg.Satisfied)
	if len(next) == 0 {
		return f.finish(r, w, reg)
	}

	if f.Pending == nil {
		return Result{}, errors.New("register: round-trip checks require a Pending store")
	}
	if err := f.Pending.Set(r, w, reg); err != nil {
		return Result{}, fmt.Errorf("register: store pending registration: %w", err)
	}

	// Kick off issuance for deliverable checks (e.g. send the email code).
	// Delivery failures are logged, not returned: the user can re-request.
	for _, c := range f.Checks {
		init, isInit := c.(Initiator)
		if !isInit || contains(reg.Satisfied, c.ID()) {
			continue
		}
		if err := init.Initiate(r.Context(), reg); err != nil {
			f.logger().Error("register: initiation failed", "loginID", reg.LoginID, "check", c.ID(), "error", err)
		}
	}
	return Result{OK: true, Next: next}, nil
}

// VerifyCheck verifies one round-trip check (e.g. the emailed code) and
// advances the pending registration. When the last check passes it creates
// the account.
//
// A missing, expired or tampered pending registration, a wrong code, and a
// replayed (already satisfied) check all come back as (Result{OK: false},
// nil). A non-nil error is an internal failure — except ErrUserExists, which
// reports that the login ID was taken while the registration was pending.
func (f *Flow) VerifyCheck(r *http.Request, w http.ResponseWriter, loginID, checkID, input string) (Result, error) {
	if err := f.check(); err != nil {
		return Result{}, err
	}
	c := f.checkByID(checkID)
	if c == nil {
		return Result{}, fmt.Errorf("register: check %q not registered", checkID)
	}
	if f.Pending == nil {
		return Result{}, errors.New("register: round-trip checks require a Pending store")
	}

	loginID = strings.TrimSpace(loginID)
	reg, err := f.Pending.Get(r, loginID)
	if err != nil || time.Now().After(reg.ExpiresAt) {
		if err != nil {
			f.logger().Debug("register: no usable pending registration", "loginID", loginID, "reason", err)
		}
		return Result{}, nil
	}

	if contains(reg.Satisfied, checkID) {
		f.logger().Debug("register: check already satisfied", "loginID", loginID, "check", checkID)
		return Result{}, nil
	}

	ok, err := c.Verify(reg.LoginID, input)
	if err != nil {
		return Result{}, fmt.Errorf("register: verify %s: %w", checkID, err)
	}
	if !ok {
		f.logger().Debug("register: check verification failed", "loginID", loginID, "check", checkID)
		return Result{}, nil
	}

	reg.Satisfied = append(reg.Satisfied, checkID)
	next := f.remaining(reg.Satisfied)
	if len(next) == 0 {
		return f.finish(r, w, reg)
	}
	if err := f.Pending.Set(r, w, reg); err != nil {
		return Result{}, fmt.Errorf("register: store pending registration: %w", err)
	}
	return Result{OK: true, Next: next}, nil
}

// Initiate re-triggers issuance for a deliverable check (e.g. resend the
// email code). The check must implement Initiator.
//
// It silently does nothing when no usable pending registration exists, and
// delivery failures are logged, not returned — the response should not
// reveal whether a registration is pending for the login ID. A non-nil error
// indicates misconfiguration (unknown check, check without issuance
// support).
func (f *Flow) Initiate(r *http.Request, loginID, checkID string) error {
	if err := f.check(); err != nil {
		return err
	}
	c := f.checkByID(checkID)
	if c == nil {
		return fmt.Errorf("register: check %q not registered", checkID)
	}
	init, isInit := c.(Initiator)
	if !isInit {
		return fmt.Errorf("register: check %q does not support initiation", checkID)
	}
	if f.Pending == nil {
		return errors.New("register: round-trip checks require a Pending store")
	}

	reg, err := f.Pending.Get(r, strings.TrimSpace(loginID))
	if err != nil || time.Now().After(reg.ExpiresAt) || contains(reg.Satisfied, checkID) {
		return nil
	}
	if err := init.Initiate(r.Context(), reg); err != nil {
		f.logger().Error("register: initiation failed", "loginID", reg.LoginID, "check", checkID, "error", err)
	}
	return nil
}

// finish is the single place an account is created. It re-checks login ID
// availability (the pending window is a race), runs every Finalizer (e.g.
// atomically consuming the invite), creates the user, optionally logs them
// in, and clears the pending registration.
//
// A Finalizer returning false (invite exhausted or revoked while pending)
// aborts with Result{OK: false} and clears the pending registration — the
// user must start over. A session failure after creation is logged but still
// reported as Done: the account exists and the user can log in normally.
func (f *Flow) finish(r *http.Request, w http.ResponseWriter, reg Registration) (Result, error) {
	exists, err := f.userExists(reg.LoginID)
	if err != nil {
		return Result{}, err
	}
	if exists {
		f.clearPending(r, w, reg.LoginID)
		return Result{}, ErrUserExists
	}

	// Finalizers run before creation: consuming an invite past its limit is
	// worse than burning one use on a failed creation.
	for _, c := range f.Checks {
		fin, isFin := c.(Finalizer)
		if !isFin {
			continue
		}
		ok, err := fin.Finalize(reg)
		if err != nil {
			return Result{}, fmt.Errorf("register: finalize %s: %w", c.ID(), err)
		}
		if !ok {
			f.logger().Debug("register: finalization failed", "loginID", reg.LoginID, "check", c.ID())
			f.clearPending(r, w, reg.LoginID)
			return Result{}, nil
		}
	}

	if err := f.Creator.CreateVerifiedUser(NewUser{
		LoginID:       reg.LoginID,
		PasswordHash:  reg.PassHash,
		Email:         reg.Email,
		EmailVerified: contains(reg.Satisfied, CheckEmail),
	}); err != nil {
		if errors.Is(err, ErrUserExists) {
			f.clearPending(r, w, reg.LoginID)
			return Result{}, ErrUserExists
		}
		return Result{}, fmt.Errorf("register: create user: %w", err)
	}

	if f.Session != nil {
		if err := f.Session.LoginUser(r, w, reg.LoginID, false); err != nil {
			f.logger().Error("register: auto-login after registration failed", "loginID", reg.LoginID, "error", err)
		}
	}
	f.clearPending(r, w, reg.LoginID)
	f.logger().Debug("register: registration complete", "loginID", reg.LoginID, "satisfied", reg.Satisfied)
	return Result{OK: true, Done: true}, nil
}

func (f *Flow) clearPending(r *http.Request, w http.ResponseWriter, loginID string) {
	if f.Pending == nil {
		return
	}
	if err := f.Pending.Clear(r, w, loginID); err != nil {
		f.logger().Error("register: failed to clear pending registration", "loginID", loginID, "error", err)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
