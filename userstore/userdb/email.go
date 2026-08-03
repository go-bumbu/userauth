package userdb

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-bumbu/userauth/support/hashutil"
	"gorm.io/gorm"
)

// StoreEmailCode persists a hashed email verification code, replacing any existing code for the user.
func (s Store) StoreEmailCode(userID, codeHash string, expiresAt time.Time) error {
	if err := s.db.Where("user_id = ?", userID).Delete(&emailVerificationCodeModel{}).Error; err != nil {
		return err
	}
	return s.db.Create(&emailVerificationCodeModel{UserID: userID, CodeHash: codeHash, ExpiresAt: expiresAt}).Error
}

// emailCodeEnabled returns whether email 2FA is enabled for the user (used by AvailableSecondFactors).
func (s Store) emailCodeEnabled(userID string) (bool, error) {
	var f secondFactorFlagsModel
	err := s.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return f.EmailEnabled, nil
}

// SetEmailCodeEnabled is a store method to enable or disable email 2FA for a user.
func (s Store) SetEmailCodeEnabled(userID string, enabled bool) error {
	var f secondFactorFlagsModel
	err := s.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	f.UserID = userID
	f.EmailEnabled = enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&f).Error
	}
	return s.db.Save(&f).Error
}

// VerifyEmailCode implements userauth.EmailCodeVerifier. Consumes the code on success if not expired.
func (s Store) VerifyEmailCode(userID, code string) (bool, error) {
	hash := hashutil.HashCodeSHA256(code)
	var m emailVerificationCodeModel
	err := s.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return false, nil
	}
	if err := s.db.Delete(&m).Error; err != nil {
		return false, err
	}
	return true, nil
}

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

// VerifyPendingEmailChange verifies the code for a pending email change and returns the new email.
// Consumes the pending change on success.
func (s Store) VerifyPendingEmailChange(userID, code string) (newEmail string, err error) {
	hash := hashutil.HashCodeSHA256(code)
	var m pendingEmailChangeModel
	err = s.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
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
