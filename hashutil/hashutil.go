// Package hashutil provides hashing and verification for passwords and recovery codes.
// It implements both generation (hash) and verification (check) for use by user stores and login flows.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// Recovery code hashing (SHA-256, for one-time codes)

// HashRecoveryCode returns a deterministic hash of the recovery code suitable for storage.
// Use when generating codes (hash before storing) and when verifying (hash user input to compare with stored hashes).
// Input is trimmed of surrounding whitespace before hashing.
func HashRecoveryCode(code string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(h[:])
}
