// Package verificationcode owns one-time verification code policy: numeric
// code generation, SHA-256 hashing, expiry, and opinionated defaults.
// Persistence is delegated to a CodeStore (implementations under store/);
// sending the code to the user is delegated to a Deliverer (implementations
// under deliver/).
package verificationcode

import (
	"context"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// CodeStore persists hashed one-time codes and consumes them atomically.
// Implementations are pure persistence: they never generate or hash codes,
// and they never decide the attempt limit — they only count.
type CodeStore interface {
	// StoreCode saves the hash for userID, replacing any previous code (and
	// its attempt count).
	StoreCode(userID, hash string, expiresAt time.Time) error
	// ConsumeCode atomically checks for a non-expired matching hash and, on
	// success, deletes it (one-time use). It returns false if the code is
	// absent, expired, or does not match. Each mismatch counts as a failed
	// attempt; when maxAttempts is reached the code is deleted, so a stored
	// code can never be guessed by exhausting its keyspace.
	ConsumeCode(userID, hash string, maxAttempts int) (bool, error)
}

// CodeVerifier verifies a one-time code at login (email, SMS, …).
type CodeVerifier interface {
	Verify(userID, code string) (bool, error)
}

// Deliverer sends a verification code to a recipient. The interface is
// transport-agnostic: implementations decide how to format and deliver the
// message (email, SMS, file, Slack, etc.).
type Deliverer interface {
	Deliver(ctx context.Context, to string, code string, expiresAt time.Time) error
}

const (
	defaultCodeLength  = 6
	defaultCodeExpiry  = 10 * time.Minute
	defaultMaxAttempts = 5
)

// Service owns one-time code policy: generation, SHA-256 hashing, expiry,
// the wrong-guess attempt limit, and opinionated defaults. Persistence is
// delegated to a CodeStore.
type Service struct {
	store       CodeStore
	codeLen     int
	expiry      time.Duration
	maxAttempts int
}

// Opts configures a Service. Zero-valued fields fall back to the package
// defaults (length 6, 10-minute expiry, 5 attempts).
type Opts struct {
	CodeLength int
	Expiry     time.Duration
	// MaxAttempts bounds wrong guesses per issued code; when reached the
	// code is invalidated. Codes are short (10^CodeLength keyspace), so an
	// attempt cap is what makes them non-brute-forceable — it cannot be
	// disabled, only sized.
	MaxAttempts int
}

// NewService wires the service to a CodeStore and applies the opinionated
// defaults for any zero-valued option.
func NewService(store CodeStore, opts Opts) *Service {
	if opts.CodeLength <= 0 {
		opts.CodeLength = defaultCodeLength
	}
	if opts.Expiry <= 0 {
		opts.Expiry = defaultCodeExpiry
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultMaxAttempts
	}
	return &Service{store: store, codeLen: opts.CodeLength, expiry: opts.Expiry, maxAttempts: opts.MaxAttempts}
}

// Generate creates a numeric code, hashes it (SHA-256), stores the hash, and
// returns the plaintext code and its expiry for the caller to deliver.
func (s *Service) Generate(userID string) (code string, expiresAt time.Time, err error) {
	code, err = hashutil.GenerateNumericCode(s.codeLen)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(s.expiry)
	if err = s.store.StoreCode(userID, hashutil.HashCodeSHA256(code), expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return code, expiresAt, nil
}

// Verify hashes the submitted code and asks the store to consume a match.
// Wrong guesses count against the code's attempt limit; once exhausted the
// code is invalidated and the user must request a new one. It implements
// CodeVerifier.
func (s *Service) Verify(userID, code string) (bool, error) {
	return s.store.ConsumeCode(userID, hashutil.HashCodeSHA256(code), s.maxAttempts)
}
