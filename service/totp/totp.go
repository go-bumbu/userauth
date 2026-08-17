// Package totp owns authenticator-app (RFC 6238) policy: secret generation,
// the enrolment ceremony (generate, confirm with a first code, enable),
// code validation, and optional encryption of the secret at rest.
// Persistence is delegated to a Store (implementations under store/); the
// consuming application owns transport and key management.
//
// Brute-force protection is deliberately not in this package: TOTP codes are
// 6 digits, and the backoff that makes that keyspace unguessable is shared
// with the other small-keyspace factors in service/throttle, applied by the
// login engine (see flow/login.TOTPMethod).
package totp

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-bumbu/userauth/service/cipher"
)

// Record is what the Store persists. Every field is opaque to the store:
// stores never generate, encrypt, or validate anything. Secret is the base32
// shared secret, or its ciphertext when the service has a Cipher configured.
type Record struct {
	Secret  string // base32 secret, or ciphertext when KeyID is set
	KeyID   string // cipher key that produced Secret; empty = stored in the clear
	Enabled bool   // false while enrolment is pending confirmation
}

// Store persists one TOTP record per user. Implementations are pure
// persistence: they never generate secrets, encrypt, or validate codes.
type Store interface {
	// Get returns the user's record, or ErrNotEnrolled if there is none.
	Get(userID string) (Record, error)
	// Set stores the record, replacing any previous one for the user.
	Set(userID string, rec Record) error
	// Delete removes the record. Deleting an absent record is not an error.
	Delete(userID string) error
}

// ErrNotEnrolled is returned by Store.Get and by service methods when the user
// has no TOTP record. It is a state, not a failure: callers offering enrolment
// treat it as "not set up yet".
var ErrNotEnrolled = errors.New("totp: user is not enrolled")

// ErrNoCipher is returned when a stored secret carries a KeyID but the service
// has no Cipher configured to decrypt it (a misconfigured key, not bad input).
var ErrNoCipher = errors.New("totp: stored secret is encrypted but no cipher is configured")

// Defaults for the code parameters. Digits and Period are fixed at the values
// every authenticator app assumes; only the clock skew is configurable.
const (
	// DefaultSkew is how many 30-second periods either side of now are
	// accepted, tolerating clock drift between server and authenticator.
	DefaultSkew = 1
)

// Service owns TOTP policy: secret generation, the enrolment ceremony, code
// validation, and encryption of the secret at rest. Persistence is delegated
// to a Store.
type Service struct {
	store  Store
	issuer string
	cipher cipher.Secret
	skew   uint
	logger *slog.Logger
}

// Opts configures a Service. Issuer is required; zero-valued fields fall back
// to the package defaults.
type Opts struct {
	// Issuer is the account label shown in authenticator apps (e.g. the
	// application name). Required.
	Issuer string
	// Cipher encrypts the shared secret at rest. Optional: when nil, secrets
	// are stored in the clear and a compromised store exposes every user's
	// second factor. Key management is the consumer's concern — the library
	// never manages keys.
	Cipher cipher.Secret
	// Skew is the number of 30-second periods either side of now that are
	// accepted. 0 uses the default (1); every extra period widens the window
	// a guesser may work in, so raise it only for known-bad clocks. Zero
	// tolerance is not offered: it rejects codes from correctly-set clients.
	Skew   uint
	Logger *slog.Logger
}

// NewService wires the service to its store and applies the defaults.
func NewService(store Store, opts Opts) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("totp: store is required")
	}
	if opts.Issuer == "" {
		return nil, fmt.Errorf("totp: issuer is required")
	}
	if opts.Skew == 0 {
		opts.Skew = DefaultSkew
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		store:  store,
		issuer: opts.Issuer,
		cipher: opts.Cipher,
		skew:   opts.Skew,
		logger: opts.Logger,
	}, nil
}

// secretContext is the AEAD context bound to an encrypted secret. It is empty
// on purpose: secrets encrypted by the pre-service userdb code path were
// written with no additional authenticated data, and binding them to the user
// ID now would make those rows undecryptable. Rotating to a bound context
// needs a re-encrypt migration.
const secretContext = ""

// encrypt returns the value to store for a plaintext secret, plus its key id.
func (s *Service) encrypt(secret string) (stored, keyID string, err error) {
	if s.cipher == nil {
		return secret, "", nil
	}
	return s.cipher.Encrypt(secret, secretContext)
}

// decrypt returns the plaintext secret of a stored record. A record with no
// KeyID is either stored in the clear or predates key ids; when a cipher is
// configured it is tried anyway, so secrets written before the KeyID column
// existed keep working.
func (s *Service) decrypt(rec Record) (string, error) {
	if rec.Secret == "" {
		return "", nil
	}
	if s.cipher == nil {
		if rec.KeyID != "" {
			return "", ErrNoCipher
		}
		return rec.Secret, nil
	}
	secret, err := s.cipher.Decrypt(rec.Secret, rec.KeyID, secretContext)
	if err != nil {
		return "", fmt.Errorf("totp: decrypt secret: %w", err)
	}
	return secret, nil
}
