// Package db provides a GORM-backed recoverycodes.Store. One row per unused
// code in the user_recovery_codes table; this package owns the model and its
// auto-migration, so a setup without recovery codes never creates the table.
//
// Persistence only: hashes are stored exactly as service/recoverycodes hands
// them over, and this store never generates, hashes or compares codes.
package db

import (
	"time"

	"github.com/go-bumbu/userauth/service/recoverycodes"
	"gorm.io/gorm"
)

// recoveryCodeModel stores one recovery code hash per row
// (user_recovery_codes table, UserID = the user's canonical ID).
type recoveryCodeModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index;not null"`
	CodeHash  string `gorm:"not null"`
	CreatedAt time.Time
}

func (recoveryCodeModel) TableName() string { return "user_recovery_codes" }

// Store is a GORM-backed recoverycodes.Store.
type Store struct {
	db *gorm.DB
}

var _ recoverycodes.Store = (*Store)(nil)

// New creates a Store and auto-migrates the user_recovery_codes table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&recoveryCodeModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Replace drops every code the user has and stores the given hashes, in one
// transaction: a half-replaced set would leave the user with codes they were
// never shown.
func (s *Store) Replace(userID string, hashes []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&recoveryCodeModel{}).Error; err != nil {
			return err
		}
		for _, h := range hashes {
			if h == "" {
				continue
			}
			if err := tx.Create(&recoveryCodeModel{UserID: userID, CodeHash: h}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// Hashes returns the hashes of the user's unused codes, oldest first.
func (s *Store) Hashes(userID string) ([]string, error) {
	var out []string
	err := s.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).
		Order("id ASC").Pluck("code_hash", &out).Error
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes one code by its exact hash; deleting an absent one is not an
// error. Scoped to the user so two users holding the same hash stay independent.
func (s *Store) Delete(userID, hash string) error {
	return s.db.Where("user_id = ? AND code_hash = ?", userID, hash).
		Delete(&recoveryCodeModel{}).Error
}

// Count returns how many unused codes the user has.
func (s *Store) Count(userID string) (int, error) {
	var count int64
	err := s.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).Count(&count).Error
	return int(count), err
}

// PurgeUser deletes every code the user holds, so a user store's delete can
// cascade here. It satisfies userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&recoveryCodeModel{}).Error
}
