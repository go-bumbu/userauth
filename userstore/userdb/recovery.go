package userdb

import (
	"github.com/go-bumbu/userauth/service/recoverycodes"
	"gorm.io/gorm"
)

// RecoveryCodeStore returns the store's recoverycodes.Store view. Persistence
// only: hashes are stored exactly as service/recoverycodes hands them over, and
// this store never generates, hashes, or compares codes.
func (s Store) RecoveryCodeStore() recoverycodes.Store { return recoveryCodeStore{s} }

// recoveryCodeStore adapts Store to recoverycodes.Store.
type recoveryCodeStore struct{ s Store }

var _ recoverycodes.Store = recoveryCodeStore{}

// Replace drops every code the user has and stores the given hashes, in one
// transaction: a half-replaced set would leave the user with codes they were
// never shown.
func (r recoveryCodeStore) Replace(userID string, hashes []string) error {
	return r.s.db.Transaction(func(tx *gorm.DB) error {
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

// Hashes returns the hashes of the user's unused codes.
func (r recoveryCodeStore) Hashes(userID string) ([]string, error) {
	var out []string
	err := r.s.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).
		Order("id ASC").Pluck("code_hash", &out).Error
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes one code by its exact hash; deleting an absent one is not an
// error. Scoped to the user so two users holding the same hash stay
// independent.
func (r recoveryCodeStore) Delete(userID, hash string) error {
	return r.s.db.Where("user_id = ? AND code_hash = ?", userID, hash).
		Delete(&recoveryCodeModel{}).Error
}

// Count returns how many unused codes the user has.
func (r recoveryCodeStore) Count(userID string) (int, error) {
	var count int64
	err := r.s.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).Count(&count).Error
	return int(count), err
}
