package userauth

import (
	"github.com/go-bumbu/userauth/internal/hashutil"
)

// ErrUnknownAlgorithm is returned by VerifyPassword when the hash format is not supported.
var ErrUnknownAlgorithm = hashutil.ErrUnknownAlgorithm

// HashPassword generates a bcrypt hash of the password. Use for storing new passwords,
// e.g. when seeding a staticusers file or creating users with a pre-hashed password.
func HashPassword(password string) (string, error) {
	return hashutil.HashPassword(password)
}

// MustHashPassword is like HashPassword but panics on error. Use for tests or when input is trusted.
func MustHashPassword(password string) string {
	return hashutil.MustHashPassword(password)
}

// VerifyPassword compares a plain password with a stored hash. Returns true if they match.
// Returns ErrUnknownAlgorithm if the hash format is not supported.
func VerifyPassword(plainPassword, hash string) (bool, error) {
	return hashutil.VerifyPassword(plainPassword, hash)
}
