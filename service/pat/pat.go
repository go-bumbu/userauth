// Package pat owns personal-access-token policy: token format, secret
// hashing, expiry, scopes, and the once-only-plaintext rule. Persistence is
// delegated to a TokenStore (default implementation in userstore/userdb,
// in-memory implementation under store/memory). It is the only package that
// ever sees a token secret.
package pat

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
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

const (
	defaultPrefix        = "pat"
	defaultMaxPerUser    = 25
	defaultTouchInterval = time.Hour
	tokenIDLength        = 8
	secretLength         = 43 // ~256 bits of base62
	maxNameLength        = 100
)

// TokenInfo is the identity a verified token asserts.
type TokenInfo struct {
	UserID  string
	LoginID string
	TokenID string
	Name    string
	Scopes  []string
}

// Service owns token policy: generation, hashing, expiry, per-user limits,
// and last-used tracking. Persistence is delegated to a TokenStore; user
// lookup (enabled check at verify time) to a userauth.UserGetter.
type Service struct {
	store         TokenStore
	users         userauth.UserGetter
	prefix        string
	maxPerUser    int // -1 = unlimited
	touchInterval time.Duration
	logger        *slog.Logger
}

// Opts configures a Service. Zero values fall back to defaults.
type Opts struct {
	// Prefix is the first token segment; default "pat". A distinctive prefix
	// (e.g. "myapp_pat") makes leaked tokens greppable by secret scanners.
	Prefix string
	// MaxPerUser limits tokens per user in Mint. 0 uses the default (25);
	// a negative value means unlimited.
	MaxPerUser int
	// TouchInterval throttles LastUsedAt writes on Verify: the write is
	// skipped while the stored value is younger than the interval. 0 uses
	// the default (1h); a negative value disables the writes entirely.
	TouchInterval time.Duration
	Logger        *slog.Logger
}

// NewService wires the service to its store and user lookup.
func NewService(store TokenStore, users userauth.UserGetter, opts Opts) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("pat: store is required")
	}
	if users == nil {
		return nil, fmt.Errorf("pat: users is required")
	}
	if opts.Prefix == "" {
		opts.Prefix = defaultPrefix
	}
	if opts.MaxPerUser == 0 {
		opts.MaxPerUser = defaultMaxPerUser
	}
	if opts.MaxPerUser < 0 {
		opts.MaxPerUser = -1
	}
	if opts.TouchInterval == 0 {
		opts.TouchInterval = defaultTouchInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		store:         store,
		users:         users,
		prefix:        opts.Prefix,
		maxPerUser:    opts.MaxPerUser,
		touchInterval: opts.TouchInterval,
		logger:        opts.Logger,
	}, nil
}

// Mint creates a token for the user and returns the full plaintext exactly
// once; only the SHA-256 hash of the secret is stored. Errors:
// ErrInvalidName, ErrInvalidExpiry, ErrTooManyTokens, or store failures.
func (s *Service) Mint(userID, name string, scopes []string, expiresAt *time.Time) (string, TokenRecord, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > maxNameLength {
		return "", TokenRecord{}, fmt.Errorf("%w: must be 1-%d characters", ErrInvalidName, maxNameLength)
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return "", TokenRecord{}, fmt.Errorf("%w: must be in the future", ErrInvalidExpiry)
	}
	if s.maxPerUser > 0 {
		existing, err := s.store.ListByUser(userID)
		if err != nil {
			return "", TokenRecord{}, err
		}
		if len(existing) >= s.maxPerUser {
			return "", TokenRecord{}, fmt.Errorf("%w: limit is %d", ErrTooManyTokens, s.maxPerUser)
		}
	}
	tokenID, err := hashutil.GenerateBase62(tokenIDLength)
	if err != nil {
		return "", TokenRecord{}, err
	}
	secret, err := hashutil.GenerateBase62(secretLength)
	if err != nil {
		return "", TokenRecord{}, err
	}
	rec := TokenRecord{
		TokenID:    tokenID,
		UserID:     userID,
		Name:       name,
		SecretHash: hashutil.HashCodeSHA256(secret),
		Scopes:     scopes,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.store.Insert(rec); err != nil {
		return "", TokenRecord{}, err
	}
	return buildToken(s.prefix, tokenID, secret), rec, nil
}

// List returns the user's token records, oldest first (metadata; SecretHash
// is present but callers rendering responses must never serialize it).
func (s *Service) List(userID string) ([]TokenRecord, error) {
	return s.store.ListByUser(userID)
}

// Revoke deletes the user's token; ErrTokenNotFound for absent or foreign IDs.
func (s *Service) Revoke(userID, tokenID string) error {
	return s.store.Delete(userID, tokenID)
}

// Verify checks a presented token and returns the identity it asserts.
// ok=false covers every credential failure — malformed token, unknown ID,
// wrong secret, expired, owner missing or disabled — indistinguishably;
// err is only returned for store or user-store I/O failures. On success the
// record's LastUsedAt is updated, throttled by TouchInterval; a failed touch
// is logged and ignored (it must not fail an otherwise valid request).
func (s *Service) Verify(presented string) (TokenInfo, bool, error) {
	tokenID, secret, ok := parseToken(s.prefix, presented)
	if !ok {
		s.logger.Debug("pat verify: malformed token")
		return TokenInfo{}, false, nil
	}
	rec, err := s.store.GetByTokenID(tokenID)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			s.logger.Debug("pat verify: unknown token id")
			return TokenInfo{}, false, nil
		}
		return TokenInfo{}, false, err
	}
	digest := hashutil.HashCodeSHA256(secret)
	if subtle.ConstantTimeCompare([]byte(digest), []byte(rec.SecretHash)) != 1 {
		s.logger.Debug("pat verify: secret mismatch", "tokenID", tokenID)
		return TokenInfo{}, false, nil
	}
	if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now()) {
		s.logger.Debug("pat verify: token expired", "tokenID", tokenID)
		return TokenInfo{}, false, nil
	}
	user, err := s.users.GetUser(rec.UserID)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) || errors.Is(err, userauth.ErrUserDisabled) {
			s.logger.Debug("pat verify: owner not found or disabled", "tokenID", tokenID)
			return TokenInfo{}, false, nil
		}
		return TokenInfo{}, false, err
	}
	if !user.Enabled {
		s.logger.Debug("pat verify: owner disabled", "tokenID", tokenID)
		return TokenInfo{}, false, nil
	}

	if s.touchInterval >= 0 &&
		(rec.LastUsedAt == nil || time.Since(*rec.LastUsedAt) >= s.touchInterval) {
		if err := s.store.Touch(tokenID, time.Now().UTC()); err != nil {
			s.logger.Warn("pat verify: failed to update last-used", "tokenID", tokenID, "err", err)
		}
	}

	return TokenInfo{
		UserID:  user.ID,
		LoginID: user.LoginID,
		TokenID: rec.TokenID,
		Name:    rec.Name,
		Scopes:  rec.Scopes,
	}, true, nil
}
