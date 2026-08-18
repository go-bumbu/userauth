package userdb

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// StorePendingEmailChange stores a pending email change, replacing any existing one for the user.
func (s Store) StorePendingEmailChange(userID, newEmail, codeHash string, expiresAt time.Time) error {
	if err := s.db.Where("user_id = ?", userID).Delete(&pendingEmailChangeModel{}).Error; err != nil {
		return err
	}
	return s.db.Create(&pendingEmailChangeModel{
		UserID:    userID,
		NewEmail:  newEmail,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
	}).Error
}

// GetPendingEmailChange returns the pending email change for a user, if any and not expired.
func (s Store) GetPendingEmailChange(userID string) (newEmail string, err error) {
	var m pendingEmailChangeModel
	err = s.db.Where("user_id = ?", userID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("no pending email change")
		}
		return "", err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return "", fmt.Errorf("pending email change expired")
	}
	return m.NewEmail, nil
}

// ConsumePendingEmailChange verifies a pending email change by its stored hash
// and returns the new address, consuming the pending change on success.
//
// It takes a hash rather than the plaintext code: hashing is policy, it belongs
// to whoever issued the code, and a store that hashes cannot be reused with a
// different scheme.
func (s Store) ConsumePendingEmailChange(userID, codeHash string) (newEmail string, err error) {
	var m pendingEmailChangeModel
	err = s.db.Where("user_id = ? AND code_hash = ?", userID, codeHash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("invalid code")
		}
		return "", err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return "", fmt.Errorf("code expired")
	}
	if err := s.db.Delete(&m).Error; err != nil {
		return "", err
	}
	return m.NewEmail, nil
}
