// Package db provides a GORM-backed pat.TokenStore. One row per token in the
// user_pats table; this package owns the model and its auto-migration, so a
// setup that offers no personal access tokens never creates the table.
//
// Persistence only: token format, hashing, expiry and the once-only-plaintext
// rule are service/pat's business.
package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
	"gorm.io/gorm"
)

// patModel stores one personal access token per row (user_pats table, UserID =
// the user's canonical ID). SecretHash is the SHA-256 hex of the token's secret
// part; the plaintext is never stored. Scopes is a JSON-encoded []string —
// opaque here, interpreted only by the consuming application.
type patModel struct {
	ID         uint   `gorm:"primaryKey"`
	TokenID    string `gorm:"uniqueIndex;not null"`
	UserID     string `gorm:"index;not null"`
	Name       string `gorm:"not null"`
	SecretHash string `gorm:"not null"`
	SecretEnc  string // encrypted secret (cipher output); empty for hash-only tokens
	KeyID      string // cipher key id for SecretEnc; empty for hash-only
	Scopes     string // JSON-encoded []string; empty when no scopes
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

func (patModel) TableName() string { return "user_pats" }

// Store is a GORM-backed pat.TokenStore.
type Store struct {
	db *gorm.DB
}

var _ pat.TokenStore = (*Store)(nil)

// New creates a Store and auto-migrates the user_pats table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&patModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Insert stores a new token record; TokenID must be unique.
func (s *Store) Insert(rec pat.TokenRecord) error {
	m, err := toModel(rec)
	if err != nil {
		return err
	}
	return s.db.Create(&m).Error
}

// GetByTokenID returns the token record or pat.ErrTokenNotFound.
func (s *Store) GetByTokenID(tokenID string) (pat.TokenRecord, error) {
	var m patModel
	err := s.db.First(&m, "token_id = ?", tokenID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return pat.TokenRecord{}, pat.ErrTokenNotFound
		}
		return pat.TokenRecord{}, err
	}
	return toRecord(m)
}

// ListByUser returns the user's token records, oldest first.
func (s *Store) ListByUser(userID string) ([]pat.TokenRecord, error) {
	var rows []patModel
	if err := s.db.Where("user_id = ?", userID).
		Order("created_at ASC, token_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]pat.TokenRecord, 0, len(rows))
	for _, m := range rows {
		rec, err := toRecord(m)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// Delete removes the token only when it belongs to userID; returns
// pat.ErrTokenNotFound for absent or foreign tokens.
func (s *Store) Delete(userID, tokenID string) error {
	res := s.db.Where("user_id = ? AND token_id = ?", userID, tokenID).Delete(&patModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return pat.ErrTokenNotFound
	}
	return nil
}

// Touch updates the token's last-used timestamp.
func (s *Store) Touch(tokenID string, t time.Time) error {
	res := s.db.Model(&patModel{}).Where("token_id = ?", tokenID).
		Update("last_used_at", t)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return pat.ErrTokenNotFound
	}
	return nil
}

// PurgeUser deletes every token the user owns, so a user store's delete can
// cascade here. It satisfies userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&patModel{}).Error
}

func toModel(rec pat.TokenRecord) (patModel, error) {
	scopes := ""
	if len(rec.Scopes) > 0 {
		b, err := json.Marshal(rec.Scopes)
		if err != nil {
			return patModel{}, fmt.Errorf("encode scopes: %w", err)
		}
		scopes = string(b)
	}
	return patModel{
		TokenID:    rec.TokenID,
		UserID:     rec.UserID,
		Name:       rec.Name,
		SecretHash: rec.SecretHash,
		SecretEnc:  rec.SecretEnc,
		KeyID:      rec.KeyID,
		Scopes:     scopes,
		ExpiresAt:  rec.ExpiresAt,
		LastUsedAt: rec.LastUsedAt,
		CreatedAt:  rec.CreatedAt,
	}, nil
}

func toRecord(m patModel) (pat.TokenRecord, error) {
	var scopes []string
	if m.Scopes != "" {
		if err := json.Unmarshal([]byte(m.Scopes), &scopes); err != nil {
			return pat.TokenRecord{}, fmt.Errorf("decode scopes: %w", err)
		}
	}
	return pat.TokenRecord{
		TokenID:    m.TokenID,
		UserID:     m.UserID,
		Name:       m.Name,
		SecretHash: m.SecretHash,
		SecretEnc:  m.SecretEnc,
		KeyID:      m.KeyID,
		Scopes:     scopes,
		ExpiresAt:  m.ExpiresAt,
		LastUsedAt: m.LastUsedAt,
		CreatedAt:  m.CreatedAt,
	}, nil
}
