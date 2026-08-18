// Package db provides a GORM-backed verificationcode.CodeStore. Outstanding
// codes live in the user_verification_codes table, one row per channel and user, and
// this package owns the model and its auto-migration.
//
// One Store instance backs one channel, matching the service's model: construct
// one for email and another for sms over the same *gorm.DB. The channel is part
// of the row key, so a user may have a code outstanding on each.
//
// Persistence only: code generation, hashing, expiry length and the size of the
// attempt budget are verificationcode.Service's business. This store counts
// wrong guesses but never decides the limit.
package db

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth/service/verificationcode"
	"gorm.io/gorm"
)

// codeModel stores one outstanding verification code per channel and user
// (user_verification_codes table). CodeHash is a hash — the plaintext code is never
// stored — and Attempts counts wrong guesses against it, which is what keeps a
// short numeric code out of reach of exhaustive guessing.
type codeModel struct {
	ID        uint      `gorm:"primaryKey"`
	Channel   string    `gorm:"index:idx_user_verification_codes_channel_user,unique;not null"`
	UserID    string    `gorm:"index:idx_user_verification_codes_channel_user,unique;not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Attempts  int       `gorm:"not null"`
	CreatedAt time.Time
}

func (codeModel) TableName() string { return "user_verification_codes" }

// Store is a GORM-backed CodeStore for one channel.
type Store struct {
	db      *gorm.DB
	channel string
}

var _ verificationcode.CodeStore = (*Store)(nil)

// New creates a Store for one channel and auto-migrates the user_verification_codes
// table. The channel is an opaque label ("email", "sms", …) that keeps a user's
// codes for different channels independent; an empty one would make two
// channels share a row and silently invalidate each other's codes, so it is
// rejected.
func New(db *gorm.DB, channel string) (*Store, error) {
	if channel == "" {
		return nil, errors.New("service/verificationcode/store/db: channel must not be empty")
	}
	if err := db.AutoMigrate(&codeModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db, channel: channel}, nil
}

// StoreCode saves the hash, replacing any previous code for the user on this
// channel — including its attempt count, because a freshly issued code gets a
// fresh budget.
func (s *Store) StoreCode(userID, hash string, expiresAt time.Time) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("channel = ? AND user_id = ?", s.channel, userID).
			Delete(&codeModel{}).Error; err != nil {
			return err
		}
		return tx.Create(&codeModel{
			Channel:   s.channel,
			UserID:    userID,
			CodeHash:  hash,
			ExpiresAt: expiresAt,
		}).Error
	})
}

// ConsumeCode checks for a non-expired matching hash and deletes it on success
// (one-time use), returning false when the code is absent, expired or wrong.
// Each mismatch costs one attempt; reaching maxAttempts deletes the code.
//
// The whole decision runs in one transaction, and the success path deletes
// conditionally on the hash and counts affected rows — so two concurrent
// submissions of the same correct code cannot both be told "yes".
func (s *Store) ConsumeCode(userID, hash string, maxAttempts int) (bool, error) {
	var consumed bool
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var m codeModel
		err := tx.Where("channel = ? AND user_id = ?", s.channel, userID).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // nothing outstanding
		}
		if err != nil {
			return err
		}

		// an expired code is discarded rather than merely rejected: the user
		// has to request a new one either way
		if time.Now().UTC().After(m.ExpiresAt) {
			return tx.Where("id = ?", m.ID).Delete(&codeModel{}).Error
		}

		if m.CodeHash != hash {
			m.Attempts++
			if m.Attempts >= maxAttempts {
				return tx.Where("id = ?", m.ID).Delete(&codeModel{}).Error
			}
			return tx.Model(&codeModel{}).Where("id = ?", m.ID).
				Update("attempts", m.Attempts).Error
		}

		res := tx.Where("id = ? AND code_hash = ?", m.ID, hash).Delete(&codeModel{})
		if res.Error != nil {
			return res.Error
		}
		consumed = res.RowsAffected == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return consumed, nil
}

// PurgeUser deletes the user's outstanding codes on every channel — not only
// this Store's channel, so one purger wired into a user store's cascade covers
// them all. It satisfies userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&codeModel{}).Error
}
