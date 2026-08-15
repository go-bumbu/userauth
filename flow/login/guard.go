package login

import (
	"errors"
	"net/http"
)

// Guard is the per-account brute-force gate of Flow.Submit: it is consulted
// before any credential work and fed the outcome of every counted
// submission. Its main customer is the password step — passwords have an
// unbounded keyspace and no server-side artifact to cap attempts on, so the
// only per-account defense is counting failures and slowing down.
//
// It is keyed by the raw login identifier the client typed — never the
// resolved user — so submissions for unknown accounts throttle exactly like
// wrong passwords for existing ones and the guard cannot become an
// account-existence oracle.
//
// The *http.Request is passed through untouched as an escape hatch for
// custom guards (per-IP keys, risk scoring, CAPTCHA decisions); the library
// itself never interprets the request.
type Guard interface {
	// Allow reports whether the submission may proceed. A denial is
	// rendered as a credential-shaped failure (uniform Result{OK:false}),
	// indistinguishable from a wrong credential.
	Allow(r *http.Request, loginID, methodID string) (bool, error)
	// Fail records a credential-shaped failure: unknown user, disabled
	// user, or wrong credential. The engine does not count out-of-order
	// submissions (method not offered) — no secret was tested.
	Fail(r *http.Request, loginID, methodID string) error
	// Success clears the failure state after an accepted factor.
	Success(r *http.Request, loginID, methodID string) error
}

// ThrottleGuard adapts a Throttle into a Guard: escalating delay per
// consecutive failure, keyed by login ID, ignoring the request. Entries are
// namespaced with a "guard:" method prefix, so the ThrottleStore instance
// may be shared with a verifier Throttle and a ResendLimiter.
type ThrottleGuard struct {
	Throttle *Throttle
}

func guardKey(methodID string) string { return "guard:" + methodID }

func (g ThrottleGuard) check() error {
	if g.Throttle == nil {
		return errors.New("login: ThrottleGuard requires a Throttle")
	}
	return nil
}

func (g ThrottleGuard) Allow(_ *http.Request, loginID, methodID string) (bool, error) {
	if err := g.check(); err != nil {
		return false, err
	}
	return g.Throttle.Allow(loginID, guardKey(methodID))
}

func (g ThrottleGuard) Fail(_ *http.Request, loginID, methodID string) error {
	if err := g.check(); err != nil {
		return err
	}
	return g.Throttle.Fail(loginID, guardKey(methodID))
}

func (g ThrottleGuard) Success(_ *http.Request, loginID, methodID string) error {
	if err := g.check(); err != nil {
		return err
	}
	return g.Throttle.Success(loginID, guardKey(methodID))
}
