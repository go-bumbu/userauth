package login

import (
	"errors"
	"time"
)

// Throttle defaults: three free failures, then 2s doubling per failure up to
// 5 minutes. With a 6-digit TOTP code this caps guessing at a rate where
// exhausting the keyspace takes years instead of hours.
const (
	DefaultFreeFailures = 3
	DefaultBaseDelay    = 2 * time.Second
	DefaultMaxDelay     = 5 * time.Minute
)

// ThrottleStore persists consecutive wrong-guess state per user and method.
// Implementations are pure persistence: they count and report, but never
// decide when an attempt is allowed (Throttle does).
type ThrottleStore interface {
	// Failures returns the consecutive failure count and the time of the most
	// recent failure. A user with no recorded failures returns (0, zero time).
	Failures(userID, method string) (count int, last time.Time, err error)
	// AddFailure increments the failure count and sets the last-failure time.
	AddFailure(userID, method string, at time.Time) error
	// Clear removes the failure state (called on successful verification).
	Clear(userID, method string) error
}

// Throttle slows down repeated wrong guesses of a login factor with an
// escalating delay: after FreeFailures consecutive failures, the next attempt
// is only allowed once BaseDelay·2^(extra failures) has passed since the last
// failure, capped at MaxDelay. Successful verification resets the count.
//
// Escalating delay is used instead of a hard lockout on purpose: a lockout
// lets anyone who knows a username deny its owner access, while backoff keeps
// the account usable and still makes small-keyspace factors (TOTP, recovery
// codes) non-brute-forceable — RFC 6238 §5.2 requires verifiers to throttle.
//
// Zero-valued fields fall back to the package defaults; Store is required.
type Throttle struct {
	Store        ThrottleStore
	FreeFailures int           // failures before delays kick in
	BaseDelay    time.Duration // first delay, doubled per further failure
	MaxDelay     time.Duration // upper bound for the delay
}

func (t *Throttle) freeFailures() int {
	if t.FreeFailures > 0 {
		return t.FreeFailures
	}
	return DefaultFreeFailures
}

func (t *Throttle) baseDelay() time.Duration {
	if t.BaseDelay > 0 {
		return t.BaseDelay
	}
	return DefaultBaseDelay
}

func (t *Throttle) maxDelay() time.Duration {
	if t.MaxDelay > 0 {
		return t.MaxDelay
	}
	return DefaultMaxDelay
}

// delay returns how long after the last failure the next attempt is allowed:
// zero while failures stay below FreeFailures, then BaseDelay doubled for
// each failure beyond that, capped at MaxDelay.
func (t *Throttle) delay(failures int) time.Duration {
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

// Allow reports whether the user may attempt the factor now. A denied attempt
// is a credential-shaped failure: verifiers should return (false, nil) so the
// engine's uniform-failure semantics hold. A non-nil error is a store failure
// (the throttle fails closed).
func (t *Throttle) Allow(userID, method string) (bool, error) {
	if t.Store == nil {
		return false, errors.New("login: throttle requires a Store")
	}
	count, last, err := t.Store.Failures(userID, method)
	if err != nil {
		return false, err
	}
	d := t.delay(count)
	if d == 0 {
		return true, nil
	}
	return time.Now().After(last.Add(d)), nil
}

// Fail records a wrong guess.
func (t *Throttle) Fail(userID, method string) error {
	if t.Store == nil {
		return errors.New("login: throttle requires a Store")
	}
	return t.Store.AddFailure(userID, method, time.Now())
}

// Success clears the failure state after a correct guess.
func (t *Throttle) Success(userID, method string) error {
	if t.Store == nil {
		return errors.New("login: throttle requires a Store")
	}
	return t.Store.Clear(userID, method)
}

// Resend limiting defaults: the second code within a minute is not issued,
// the wait doubles per further request up to 15 minutes, and the counter is
// forgotten an hour after the last request.
const (
	DefaultResendInterval = time.Minute
	DefaultResendMaxWait  = 15 * time.Minute
	DefaultResendReset    = time.Hour
)

// ResendLimiter bounds how often a deliverable factor (email, SMS) may be
// issued per user: the first code is free, then each further request must
// wait Interval doubled per consecutive request, capped at MaxWait. State is
// forgotten ResetAfter after the last request. Without it Flow.Initiate is an
// email/SMS bombing relay (and for SMS, a cost attack) — and since every new
// code replaces the previous one, limiting issuance also keeps a guesser from
// refreshing the small code keyspace at will.
//
// It shares the ThrottleStore interface; entries are namespaced with an
// "initiate:" method prefix, so a store instance may be shared with a
// Throttle. Zero-valued fields fall back to the package defaults; Store is
// required.
type ResendLimiter struct {
	Store      ThrottleStore
	Interval   time.Duration // wait after the first request, doubled per further one
	MaxWait    time.Duration // upper bound for the wait
	ResetAfter time.Duration // forget the counter this long after the last request
}

func (l *ResendLimiter) interval() time.Duration {
	if l.Interval > 0 {
		return l.Interval
	}
	return DefaultResendInterval
}

func (l *ResendLimiter) maxWait() time.Duration {
	if l.MaxWait > 0 {
		return l.MaxWait
	}
	return DefaultResendMaxWait
}

func (l *ResendLimiter) resetAfter() time.Duration {
	if l.ResetAfter > 0 {
		return l.ResetAfter
	}
	return DefaultResendReset
}

func resendKey(methodID string) string { return "initiate:" + methodID }

// Allow reports whether a code may be issued for the user and method now.
// Denied issuance must stay invisible to the client (same response either
// way) — Flow.Initiate treats it like the other silently-skipped cases. A
// non-nil error is a store failure (the limiter fails closed).
func (l *ResendLimiter) Allow(userID, methodID string) (bool, error) {
	if l.Store == nil {
		return false, errors.New("login: resend limiter requires a Store")
	}
	count, last, err := l.Store.Failures(userID, resendKey(methodID))
	if err != nil {
		return false, err
	}
	if count == 0 {
		return true, nil
	}
	if time.Now().After(last.Add(l.resetAfter())) {
		if err := l.Store.Clear(userID, resendKey(methodID)); err != nil {
			return false, err
		}
		return true, nil
	}
	wait := l.interval()
	max := l.maxWait()
	for i := 1; i < count; i++ {
		wait *= 2
		if wait >= max {
			wait = max
			break
		}
	}
	return time.Now().After(last.Add(wait)), nil
}

// Record counts an issuance.
func (l *ResendLimiter) Record(userID, methodID string) error {
	if l.Store == nil {
		return errors.New("login: resend limiter requires a Store")
	}
	return l.Store.AddFailure(userID, resendKey(methodID), time.Now())
}
