// Package throttle owns brute-force backoff policy: an escalating delay per
// consecutive failure, keyed by an identifier and a method. It is consumed
// by the login engine (factor verification, the per-account submission
// guard, issuance rate limiting) and by per-request authenticators
// (basicauth). Persistence is delegated to a Store (implementations under
// store/).
package throttle

import (
	"errors"
	"time"
)

// Defaults: three free failures, then 2s doubling per failure up to 5
// minutes. With a 6-digit TOTP code this caps guessing at a rate where
// exhausting the keyspace takes years instead of hours.
const (
	DefaultFreeFailures = 3
	DefaultBaseDelay    = 2 * time.Second
	DefaultMaxDelay     = 5 * time.Minute
)

// Store persists consecutive failure state per key and method.
// Implementations are pure persistence: they count and report, but never
// decide when an attempt is allowed (Backoff does).
type Store interface {
	// Failures returns the consecutive failure count and the time of the
	// most recent failure. A key with no recorded failures returns
	// (0, zero time).
	Failures(key, method string) (count int, last time.Time, err error)
	// AddFailure increments the failure count and sets the last-failure time.
	AddFailure(key, method string, at time.Time) error
	// Clear removes the failure state (called on success).
	Clear(key, method string) error
}

// Backoff slows down repeated failures with an escalating delay: after
// FreeFailures consecutive failures, the next attempt is only allowed once
// BaseDelay·2^(extra failures) has passed since the last failure, capped at
// MaxDelay. Success resets the count.
//
// Escalating delay is used instead of a hard lockout on purpose: a lockout
// lets anyone who knows an identifier deny its owner access, while backoff
// keeps the account usable and still makes small-keyspace factors (TOTP,
// recovery codes) non-brute-forceable — RFC 6238 §5.2 requires verifiers to
// throttle.
//
// Zero-valued fields fall back to the package defaults; Store is required.
type Backoff struct {
	Store        Store
	FreeFailures int           // failures before delays kick in
	BaseDelay    time.Duration // first delay, doubled per further failure
	MaxDelay     time.Duration // upper bound for the delay
}

func (t *Backoff) freeFailures() int {
	if t.FreeFailures > 0 {
		return t.FreeFailures
	}
	return DefaultFreeFailures
}

func (t *Backoff) baseDelay() time.Duration {
	if t.BaseDelay > 0 {
		return t.BaseDelay
	}
	return DefaultBaseDelay
}

func (t *Backoff) maxDelay() time.Duration {
	if t.MaxDelay > 0 {
		return t.MaxDelay
	}
	return DefaultMaxDelay
}

// delay returns how long after the last failure the next attempt is allowed:
// zero while failures stay below FreeFailures, then BaseDelay doubled for
// each failure beyond that, capped at MaxDelay.
func (t *Backoff) delay(failures int) time.Duration {
	extra := failures - t.freeFailures()
	if extra < 0 {
		return 0
	}
	d := t.baseDelay()
	max := t.maxDelay()
	for i := 0; i < extra; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}

// Allow reports whether the key may attempt the method now. Callers should
// render a denial exactly like a credential failure. A non-nil error is a
// store failure (the backoff fails closed).
func (t *Backoff) Allow(key, method string) (bool, error) {
	if t.Store == nil {
		return false, errors.New("throttle: backoff requires a Store")
	}
	count, last, err := t.Store.Failures(key, method)
	if err != nil {
		return false, err
	}
	d := t.delay(count)
	if d == 0 {
		return true, nil
	}
	return time.Now().After(last.Add(d)), nil
}

// Fail records a failure.
func (t *Backoff) Fail(key, method string) error {
	if t.Store == nil {
		return errors.New("throttle: backoff requires a Store")
	}
	return t.Store.AddFailure(key, method, time.Now())
}

// Success clears the failure state.
func (t *Backoff) Success(key, method string) error {
	if t.Store == nil {
		return errors.New("throttle: backoff requires a Store")
	}
	return t.Store.Clear(key, method)
}
