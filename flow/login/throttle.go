package login

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth/service/throttle"
)

// Throttle is the backoff used by this engine's verifiers and guard; see
// service/throttle.Backoff for the policy (escalating delay, never a hard
// lockout) and throttle/store for the persistence adapters.
type Throttle = throttle.Backoff

// ThrottleStore persists consecutive failure state; alias of
// service/throttle.Store.
type ThrottleStore = throttle.Store

// Re-exported backoff defaults; see service/throttle.
const (
	DefaultFreeFailures = throttle.DefaultFreeFailures
	DefaultBaseDelay    = throttle.DefaultBaseDelay
	DefaultMaxDelay     = throttle.DefaultMaxDelay
)

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
