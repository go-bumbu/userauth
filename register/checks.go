package register

import (
	"context"
	"time"

	"github.com/go-bumbu/userauth"
)

// Well-known check IDs. Transports refer to checks by these strings; custom
// checks may introduce their own.
const (
	CheckEmail  = "email"
	CheckInvite = "invite"
)

// Check is one registration requirement. All configured checks must pass
// before the account is created.
//
// Verify must return (false, nil) for wrong input and reserve errors for
// internal failures — the engine maps errors to 5xx-shaped results, never to
// "try again".
type Check interface {
	ID() string
	Verify(loginID, input string) (bool, error)
}

// PreVerifier is a check that can be verified synchronously at Start from
// the submitted input (e.g. an invite code), without a round trip. The
// engine runs PreVerify instead of asking the user for a later submission.
type PreVerifier interface {
	PreVerify(in StartInput) (bool, error)
}

// Initiator is the optional issuance side of a deliverable check: generate a
// code, persist it, deliver it. Round-trip checks that need a prior server
// action (email verification) implement it.
type Initiator interface {
	Initiate(ctx context.Context, reg Registration) error
}

// Finalizer is an optional hook that runs inside the engine's single account
// creation point, just before the user is created. Returning false aborts
// the registration (uniform Result{OK:false}) and clears the pending state.
// InviteCheck uses it to consume the invite atomically at creation.
type Finalizer interface {
	Finalize(reg Registration) (bool, error)
}

// CodeService issues and verifies one-time codes.
// *userauth.VerificationCodeService satisfies this.
type CodeService interface {
	Generate(userID string) (code string, expiresAt time.Time, err error)
	Verify(userID, code string) (bool, error)
}

// EmailCheck requires proving control of the registration email: Initiate
// generates a one-time code and delivers it to the pending registration's
// email; Verify consumes it.
//
// Deliverers should queue the message and return — a slow synchronous
// deliverer lets response timing reveal whether a code was issued.
type EmailCheck struct {
	Codes   CodeService
	Deliver userauth.Deliverer
}

func (c EmailCheck) ID() string { return CheckEmail }

func (c EmailCheck) Verify(loginID, input string) (bool, error) {
	return c.Codes.Verify(loginID, input)
}

// Initiate generates, stores and delivers a fresh code to the registration
// email.
func (c EmailCheck) Initiate(ctx context.Context, reg Registration) error {
	code, expiresAt, err := c.Codes.Generate(reg.LoginID)
	if err != nil {
		return err
	}
	return c.Deliver.Deliver(ctx, reg.Email, code, expiresAt)
}

// InviteCheck requires a valid invite code. It is pre-verified at Start
// (fail fast, read-only) and consumed atomically at account creation via
// Finalize — an invite exhausted or revoked while the registration was
// pending aborts it.
type InviteCheck struct {
	Invites InviteConsumer
}

func (c InviteCheck) ID() string { return CheckInvite }

// Verify always fails: the invite code must be part of StartInput so that
// Finalize can consume it at account creation. Submitting it as a round-trip
// check would leave Registration.InviteCode empty and abort at Finalize.
func (c InviteCheck) Verify(_, _ string) (bool, error) {
	return false, nil
}

func (c InviteCheck) PreVerify(in StartInput) (bool, error) {
	return c.Invites.Validate(in.InviteCode, in.Email)
}

func (c InviteCheck) Finalize(reg Registration) (bool, error) {
	return c.Invites.Consume(reg.InviteCode, reg.Email)
}
