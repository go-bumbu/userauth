// Package login is a composable login engine: a login attempt accumulates
// verified factors (password, TOTP, email code, …) until a Policy says the
// requirements are met, and only then is a session created.
//
// It owns the security invariants that callers tend to get wrong:
//
//   - the user must exist and be enabled at every step, not just the first
//   - a factor only counts if the policy currently offers it (no submitting
//     TOTP before password, no double-counting a replayed factor)
//   - all credential failures (unknown user, disabled user, wrong code,
//     method not offered) produce the same Result, so transports can stay
//     enumeration-safe without trying
//   - attempts expire, and the session is created in exactly one place
//
// Callers compose requirements at the policy level (see RequireAny and
// Chain) and keep ownership of the transport: forms, JSON, rendering.
package login

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth"
)

// DefaultAttemptExpiry bounds how long a partially completed login stays valid.
const DefaultAttemptExpiry = 5 * time.Minute

// Attempt is the server-side state of a login in progress.
//
// Satisfied is an authentication claim: whoever controls it can skip factors.
// AttemptStore implementations MUST keep it server-side or in an
// authenticated (signed/encrypted) client token — never in a plain cookie.
type Attempt struct {
	UserID    string
	Satisfied []string // method IDs verified so far, in order
	ExpiresAt time.Time

	// SessionKeepLoggedIn is not part of the authentication decision: it is
	// carried through the flow and only applied at the end, when the session
	// is created. It is captured from the first accepted factor submission.
	SessionKeepLoggedIn bool
}

// AttemptStore persists login attempts between factor submissions.
// Implementations key by Attempt.UserID.
type AttemptStore interface {
	Set(r *http.Request, w http.ResponseWriter, a Attempt) error
	Get(r *http.Request, userID string) (Attempt, error)
	Clear(r *http.Request, w http.ResponseWriter, userID string) error
}

// UserLogin creates a session for an authenticated user.
// authhandler/cookieauth.Manager satisfies this implicitly.
type UserLogin interface {
	LoginUser(r *http.Request, w http.ResponseWriter, userID string, keepLoggedIn bool) error
}

// Result is the outcome of a Submit call.
//
// OK=false means the submission was rejected for a credential-shaped reason
// (unknown or disabled user, wrong input, factor not currently offered). The
// engine deliberately does not say which, so transports can render one
// uniform failure and stay enumeration-safe.
type Result struct {
	OK   bool     // the submitted factor was accepted
	Done bool     // all requirements met; the session has been created
	Next []string // when OK && !Done: method IDs the user may attempt next
}

// Flow is the login engine. Users, Policy and Session are required.
//
// Attempts may be nil for flows whose policy always completes in a single
// submission (per-request authenticators like basic auth or trusted-header
// auth): no attempt is ever persisted then. A multi-step policy with a nil
// Attempts store fails with an error at the first incomplete submission.
type Flow struct {
	Users    userauth.UserGetter
	Methods  []Method
	Policy   Policy
	Attempts AttemptStore
	Session  UserLogin
	Expiry   time.Duration // attempt lifetime; defaults to DefaultAttemptExpiry
	Logger   *slog.Logger  // optional; defaults to slog.Default()
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
	return DefaultAttemptExpiry
}

func (f *Flow) method(id string) Method {
	for _, m := range f.Methods {
		if m.ID() == id {
			return m
		}
	}
	return nil
}

func (f *Flow) check() error {
	if f.Users == nil || f.Policy == nil || f.Session == nil {
		return errors.New("login: Users, Policy and Session are required")
	}
	return nil
}

// loadAttempt returns the current attempt for the user, or a fresh one when
// none exists (including when no store is configured) or the stored one has
// expired. Store errors are treated as "no attempt": the safe consequence is
// that the user re-verifies factors.
func (f *Flow) loadAttempt(r *http.Request, userID string) Attempt {
	if f.Attempts == nil {
		return Attempt{UserID: userID, ExpiresAt: time.Now().Add(f.expiry())}
	}
	att, err := f.Attempts.Get(r, userID)
	if err == nil && time.Now().Before(att.ExpiresAt) {
		return att
	}
	if err != nil {
		f.logger().Debug("login: no usable attempt, starting fresh", "userID", userID, "reason", err)
	}
	return Attempt{UserID: userID, ExpiresAt: time.Now().Add(f.expiry())}
}

// getEnabledUser is the shared known-and-enabled gate. The bool is false for
// any credential-shaped reason; a non-nil error is an internal store failure.
func (f *Flow) getEnabledUser(userID string) (userauth.User, bool, error) {
	user, err := f.Users.GetUser(userID)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) {
			f.logger().Debug("login: unknown user", "userID", userID)
			return userauth.User{}, false, nil
		}
		return userauth.User{}, false, err
	}
	if !user.Enabled {
		f.logger().Debug("login: user disabled", "userID", userID)
		return userauth.User{}, false, nil
	}
	return user, true, nil
}

// Submit verifies one factor and advances the attempt. When the policy is
// satisfied it creates the session and clears the attempt.
//
// keepLoggedIn is recorded on the first accepted factor of an attempt (see
// Attempt.SessionKeepLoggedIn) and only used when the session is eventually
// created; later submissions cannot change it.
//
// A non-nil error is an internal failure (misconfiguration, store or
// verifier breakage) that transports should render as a generic 5xx. All
// credential failures come back as (Result{OK: false}, nil).
func (f *Flow) Submit(r *http.Request, w http.ResponseWriter, userID, methodID, input string, keepLoggedIn bool) (Result, error) {
	if err := f.check(); err != nil {
		return Result{}, err
	}
	m := f.method(methodID)
	if m == nil {
		return Result{}, fmt.Errorf("login: method %q not registered", methodID)
	}

	user, ok, err := f.getEnabledUser(userID)
	if err != nil || !ok {
		return Result{}, err
	}

	// From here on, use the canonical user.Id: attempts, verifiers and the
	// session must all agree on the same key.
	att := f.loadAttempt(r, user.Id)
	if len(att.Satisfied) == 0 {
		att.SessionKeepLoggedIn = keepLoggedIn
	}

	// A factor only counts when the policy is currently offering it.
	_, next, err := f.Policy.Next(user, att.Satisfied)
	if err != nil {
		return Result{}, err
	}
	if !contains(next, methodID) {
		f.logger().Debug("login: method not offered", "userID", user.Id, "method", methodID, "satisfied", att.Satisfied)
		return Result{}, nil
	}

	ok, err = m.Verify(user.Id, input)
	if err != nil {
		return Result{}, fmt.Errorf("login: verify %s: %w", methodID, err)
	}
	if !ok {
		f.logger().Debug("login: factor verification failed", "userID", user.Id, "method", methodID)
		return Result{}, nil
	}

	att.Satisfied = append(att.Satisfied, methodID)
	done, next, err := f.Policy.Next(user, att.Satisfied)
	if err != nil {
		return Result{}, err
	}
	if done {
		if err := f.Session.LoginUser(r, w, user.Id, att.SessionKeepLoggedIn); err != nil {
			return Result{}, fmt.Errorf("login: create session: %w", err)
		}
		if f.Attempts != nil {
			if err := f.Attempts.Clear(r, w, user.Id); err != nil {
				f.logger().Error("login: failed to clear attempt", "userID", user.Id, "error", err)
			}
		}
		f.logger().Debug("login: login complete", "userID", user.Id, "satisfied", att.Satisfied)
		return Result{OK: true, Done: true}, nil
	}

	if f.Attempts == nil {
		return Result{}, errors.New("login: multi-step policy requires an Attempts store")
	}
	if err := f.Attempts.Set(r, w, att); err != nil {
		return Result{}, fmt.Errorf("login: store attempt: %w", err)
	}
	return Result{OK: true, Next: next}, nil
}

// Initiate triggers issuance for a deliverable factor (e.g. generate and send
// an email code). The method must implement Initiator.
//
// It is enumeration-safe by construction: issuance is silently skipped for
// unknown or disabled users and for methods the policy is not currently
// offering, and delivery failures are logged, not returned. Callers should
// render the same response regardless. A non-nil error indicates
// misconfiguration (unknown method, method without issuance support).
//
// Note: when the Initiator delivers synchronously (e.g. blocking SMTP),
// response timing can still reveal whether issuance happened; deliverers
// should queue and return.
func (f *Flow) Initiate(r *http.Request, userID, methodID string) error {
	if err := f.check(); err != nil {
		return err
	}
	m := f.method(methodID)
	if m == nil {
		return fmt.Errorf("login: method %q not registered", methodID)
	}
	init, isInit := m.(Initiator)
	if !isInit {
		return fmt.Errorf("login: method %q does not support initiation", methodID)
	}

	user, ok, err := f.getEnabledUser(userID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	att := f.loadAttempt(r, user.Id)
	_, next, err := f.Policy.Next(user, att.Satisfied)
	if err != nil {
		return err
	}
	if !contains(next, methodID) {
		f.logger().Debug("login: initiation for method not offered", "userID", user.Id, "method", methodID)
		return nil
	}

	if err := init.Initiate(r.Context(), user); err != nil {
		f.logger().Error("login: initiation failed", "userID", user.Id, "method", methodID, "error", err)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
