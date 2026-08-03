package userdb

import (
	"fmt"

	"github.com/go-bumbu/userauth/internal/hashutil"
	"gorm.io/gorm"
)

// MaxRecoveryCodes is the maximum number of recovery codes allowed per user in SetRecoveryCodes.
const MaxRecoveryCodes = 6

// SetRecoveryCodes is a store method. Replaces all codes for the user. Accepts at most MaxRecoveryCodes.
// Delete and inserts run in a single transaction.
func (s Store) SetRecoveryCodes(userID string, hashedCodes []string) error {
	if len(hashedCodes) > MaxRecoveryCodes {
		return fmt.Errorf("recovery codes: at most %d allowed, got %d", MaxRecoveryCodes, len(hashedCodes))
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&recoveryCodeModel{}).Error; err != nil {
			return err
		}
		for _, h := range hashedCodes {
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

// VerifyRecoveryCode implements userauth.RecoveryCodeVerifier. Consumes the code on success.
// Loads all stored bcrypt hashes for the user and compares against each (max 6 codes).
func (s Store) VerifyRecoveryCode(userID, code string) (bool, error) {
	var codes []recoveryCodeModel
	err := s.db.Where("user_id = ?", userID).Find(&codes).Error
	if err != nil {
		return false, err
	}
	for _, m := range codes {
		if hashutil.VerifyRecoveryCodeHash(code, m.CodeHash) {
			if err := s.db.Delete(&m).Error; err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// GetRecoveryCodesCount is a store method.
func (s Store) GetRecoveryCodesCount(userID string) (int, error) {
	var count int64
	err := s.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).Count(&count).Error
	return int(count), err
}
