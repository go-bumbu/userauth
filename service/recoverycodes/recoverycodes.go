// Package recoverycodes owns one-time recovery code policy: generation, bcrypt
// hashing, the per-user count, and single-use consumption. Persistence is
// delegated to a Store (implementations under store/).
//
// Recovery codes are a factor in their own right, not a TOTP detail: they let a
// user who lost their authenticator (or their phone, for SMS codes) back into
// the account. A consumer turning two-factor authentication on or off should
// issue or clear them alongside the primary factor.
//
// Brute-force protection lives outside this package: codes are short, and the
// shared backoff in service/throttle is what makes them unguessable (applied by
// flow/login.RecoveryMethod).
package recoverycodes

import (
	"fmt"
	"log/slog"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// Store persists the bcrypt hashes of a user's unused recovery codes.
// Implementations are pure persistence: they never generate, hash, or compare
// codes, and they do not decide how many a user gets.
type Store interface {
	// Replace atomically drops every code the user has and stores the given
	// hashes. An empty or nil slice clears them.
	Replace(userID string, hashes []string) error
	// Hashes returns the hashes of the user's unused codes, in any order. A
	// user with none returns an empty slice, not an error.
	Hashes(userID string) ([]string, error)
	// Delete removes one code by its exact stored hash (consuming it).
	// Deleting an absent hash is not an error.
	Delete(userID, hash string) error
	// Count returns how many unused codes the user has.
	Count(userID string) (int, error)
}

// DefaultCount is how many codes Issue generates when Opts.Count is zero.
// Enough that a user can lose a few printed codes, few enough to stay
// printable — and each extra code is another guess an attacker gets.
const DefaultCount = 6

// maxCount bounds Opts.Count. The verification cost is linear in the number of
// stored codes (every wrong guess bcrypt-compares against all of them), so an
// unbounded count would be a self-inflicted denial of service.
const maxCount = 20

// Service owns recovery code policy: generation, bcrypt hashing, how many a
// user gets, and single-use consumption. Persistence is delegated to a Store.
type Service struct {
	store  Store
	count  int
	logger *slog.Logger
}

// Opts configures a Service. Zero-valued fields fall back to the defaults.
type Opts struct {
	// Count is how many codes Issue generates. 0 uses DefaultCount (6); the
	// maximum is 20.
	Count  int
	Logger *slog.Logger
}

// NewService wires the service to its store and applies the defaults.
func NewService(store Store, opts Opts) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("recoverycodes: store is required")
	}
	if opts.Count == 0 {
		opts.Count = DefaultCount
	}
	if opts.Count < 0 || opts.Count > maxCount {
		return nil, fmt.Errorf("recoverycodes: count must be 1..%d, got %d", maxCount, opts.Count)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, count: opts.Count, logger: opts.Logger}, nil
}

// Issue generates a fresh set of codes for the user and returns the plaintext
// exactly once — only bcrypt hashes are stored, so a lost set cannot be
// re-shown, only re-issued.
//
// It replaces any codes the user already had: that is what makes it double as
// "regenerate", and it means a user who suspects their printed codes leaked can
// invalidate them by asking for new ones.
func (s *Service) Issue(userID string) ([]string, error) {
	if userID == "" {
		return nil, fmt.Errorf("recoverycodes: userID is required")
	}
	plain, err := hashutil.GenerateRecoveryCodes(s.count)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(plain))
	for _, c := range plain {
		h, err := hashutil.HashRecoveryCode(c)
		if err != nil {
			return nil, fmt.Errorf("recoverycodes: hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	if err := s.store.Replace(userID, hashes); err != nil {
		return nil, err
	}
	s.logger.Info("recovery codes issued", "user", userID, "count", len(plain))
	return plain, nil
}

// VerifyRecoveryCode checks a code against the user's unused codes and consumes
// the one that matches, so each code works exactly once. It implements
// userauth.RecoveryCodeVerifier.
//
// It returns (false, nil) for a wrong code or a user with no codes, reserving
// errors for store failures. Codes are bcrypt-hashed, so this compares against
// every stored hash — deliberately slow, and bounded by maxCount.
func (s *Service) VerifyRecoveryCode(userID, code string) (bool, error) {
	if code == "" {
		return false, nil
	}
	hashes, err := s.store.Hashes(userID)
	if err != nil {
		return false, err
	}
	for _, h := range hashes {
		if !hashutil.VerifyRecoveryCodeHash(code, h) {
			continue
		}
		if err := s.store.Delete(userID, h); err != nil {
			return false, err
		}
		s.logger.Info("recovery code consumed", "user", userID)
		return true, nil
	}
	return false, nil
}

// Remaining reports how many unused codes the user has, for a "you have N codes
// left" prompt.
func (s *Service) Remaining(userID string) (int, error) {
	return s.store.Count(userID)
}

// Clear removes every code for the user, e.g. when two-factor authentication is
// switched off.
func (s *Service) Clear(userID string) error {
	if err := s.store.Replace(userID, nil); err != nil {
		return err
	}
	s.logger.Info("recovery codes cleared", "user", userID)
	return nil
}
