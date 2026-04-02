// Package hashutil provides hashing and verification for passwords and recovery codes.
// It implements both generation (hash) and verification (check) for use by user stores and login flows.
package hashutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing (bcrypt)

// HashAlgo identifies the algorithm used for a stored password hash.
type HashAlgo int

const (
	Unknown HashAlgo = iota
	Bcrypt
)

// Bcrypt prefix constants for algorithm detection.
const (
	BcryptPrefix1  = "$2$"
	BcryptPrefix2a = "$2a$"
	BcryptPrefix2b = "$2b$"
	BcryptPrefix2x = "$2x$"
	BcryptPrefix2y = "$2y$"
)

var bcryptPrefixes = []string{BcryptPrefix2a, BcryptPrefix2b, BcryptPrefix2x, BcryptPrefix2y}

// Alg returns the algorithm used by the given hash string.
func Alg(hash string) HashAlgo {
	if isBcryptHash(hash) {
		return Bcrypt
	}
	return Unknown
}

func isBcryptHash(hash string) bool {
	if strings.HasPrefix(hash, BcryptPrefix1) {
		return true
	}
	if len(hash) >= 4 && contains(bcryptPrefixes, hash[:4]) {
		return true
	}
	return false
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ErrUnknownAlgorithm is returned when the hash format is not supported.
var ErrUnknownAlgorithm = errors.New("unknown crypto algorithm")

// HashPassword generates a bcrypt hash of the password. Use for storing new passwords.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// MustHashPassword is like HashPassword but panics on error. Use for tests or when input is trusted.
func MustHashPassword(password string) string {
	h, err := HashPassword(password)
	if err != nil {
		panic(err)
	}
	return h
}

// VerifyPassword compares a plain password with a stored hash. Returns true if they match.
// Returns ErrUnknownAlgorithm if the hash format is not supported.
func VerifyPassword(plainPassword, hash string) (bool, error) {
	switch Alg(hash) {
	case Bcrypt:
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("%w", ErrUnknownAlgorithm)
	}
}

// Recovery code hashing (bcrypt for recovery codes, SHA-256 for short-lived verification codes)

// recoveryCodeCharset is alphanumeric (lowercase + digits) for recovery codes.
const recoveryCodeCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

// recoveryCodeLength is the length of each generated recovery code.
const recoveryCodeLength = 8

// GenerateRecoveryCodes returns count plain recovery codes (e.g. for display once to the user). Caller hashes and stores via RecoveryCodeConfigurator.SetRecoveryCodes.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 || count > 100 {
		return nil, fmt.Errorf("GenerateRecoveryCodes: count must be 1..100, got %d", count)
	}
	out := make([]string, 0, count)
	charsetLen := big.NewInt(int64(len(recoveryCodeCharset)))
	for i := 0; i < count; i++ {
		var code []byte
		for j := 0; j < recoveryCodeLength; j++ {
			n, err := rand.Int(rand.Reader, charsetLen)
			if err != nil {
				return nil, err
			}
			code = append(code, recoveryCodeCharset[n.Int64()])
		}
		out = append(out, string(code))
	}
	return out, nil
}

// HashRecoveryCode returns a bcrypt hash of the recovery code suitable for storage.
// Use when generating recovery codes (hash before storing). Recovery codes are low-entropy,
// so bcrypt's slow hashing prevents brute-force attacks on a stolen database.
// Input is trimmed of surrounding whitespace before hashing.
func HashRecoveryCode(code string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(code)), bcrypt.DefaultCost)
	return string(b), err
}

// VerifyRecoveryCodeHash compares a plain recovery code against a bcrypt hash.
// Returns true if they match.
func VerifyRecoveryCodeHash(code, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(strings.TrimSpace(code)))
	return err == nil
}

// HashCodeSHA256 returns a deterministic SHA-256 hash of the code, hex-encoded.
// Use for short-lived verification codes (email, SMS) where deterministic DB lookup is needed
// and the code expires quickly, making brute-force impractical.
// Input is trimmed of surrounding whitespace before hashing.
func HashCodeSHA256(code string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(h[:])
}
