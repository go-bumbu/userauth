// Package pat owns personal-access-token policy: token format, secret
// hashing, expiry, scopes, and the once-only-plaintext rule. Persistence is
// delegated to a TokenStore (default implementation in userstore/userdb,
// in-memory implementation under store/memory). It is the only package that
// ever sees a token secret.
package pat

import (
	"errors"
	"strings"
	"time"
)

// TokenRecord is what the store persists. All fields are opaque to the store:
// stores never generate, hash, or interpret anything.
type TokenRecord struct {
	TokenID    string     // public lookup key, unique
	UserID     string     // owning user (canonical ID)
	Name       string     // user-given label
	SecretHash string     // SHA-256 hex of the secret part; never the plaintext
	Scopes     []string   // opaque strings, interpreted only by the consuming app
	ExpiresAt  *time.Time // nil = never expires
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// TokenStore persists token records. Implementations are pure persistence.
type TokenStore interface {
	// Insert stores a new record. TokenID must be unique.
	Insert(rec TokenRecord) error
	// GetByTokenID returns the record or ErrTokenNotFound.
	GetByTokenID(tokenID string) (TokenRecord, error)
	// ListByUser returns all records for the user, oldest first.
	ListByUser(userID string) ([]TokenRecord, error)
	// Delete removes the record only if it belongs to userID; returns
	// ErrTokenNotFound for absent or foreign tokens.
	Delete(userID, tokenID string) error
	// Touch updates LastUsedAt.
	Touch(tokenID string, t time.Time) error
}

// ErrTokenNotFound is returned for absent or foreign tokens.
var ErrTokenNotFound = errors.New("token not found")

// ErrTooManyTokens is returned by Mint when the per-user limit is reached.
var ErrTooManyTokens = errors.New("too many tokens")

// ErrInvalidName is returned by Mint for an empty or over-long name.
var ErrInvalidName = errors.New("invalid token name")

// ErrInvalidExpiry is returned by Mint for an expiry in the past.
var ErrInvalidExpiry = errors.New("invalid token expiry")

// buildToken assembles the wire format <prefix>_<tokenID>_<secret>.
func buildToken(prefix, tokenID, secret string) string {
	return prefix + "_" + tokenID + "_" + secret
}

// parseToken splits a presented token on its last two underscores, so the
// prefix itself may contain underscores. ok is false for anything malformed
// or with a non-matching prefix.
func parseToken(prefix, presented string) (tokenID, secret string, ok bool) {
	i := strings.LastIndexByte(presented, '_')
	if i < 0 {
		return "", "", false
	}
	secret = presented[i+1:]
	rest := presented[:i]
	j := strings.LastIndexByte(rest, '_')
	if j < 0 {
		return "", "", false
	}
	tokenID = rest[j+1:]
	if rest[:j] != prefix || tokenID == "" || secret == "" {
		return "", "", false
	}
	return tokenID, secret, true
}
