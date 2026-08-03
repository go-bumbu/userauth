package userdb

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
	"gorm.io/gorm"
)

// StoreSMSCode persists a hashed SMS verification code, replacing any existing code for the user.
func (s Store) StoreSMSCode(userID, codeHash string, expiresAt time.Time) error {
	if err := s.db.Where("user_id = ?", userID).Delete(&smsVerificationCodeModel{}).Error; err != nil {
		return err
	}
	return s.db.Create(&smsVerificationCodeModel{UserID: userID, CodeHash: codeHash, ExpiresAt: expiresAt}).Error
}

// smsCodeEnabled returns whether SMS 2FA is enabled for the user (used by AvailableSecondFactors).
func (s Store) smsCodeEnabled(userID string) (bool, error) {
	var f secondFactorFlagsModel
	err := s.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return f.SMSEnabled, nil
}

// SetSMSCodeEnabled is a store method to enable or disable SMS 2FA for a user.
func (s Store) SetSMSCodeEnabled(userID string, enabled bool) error {
	var f secondFactorFlagsModel
	err := s.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	f.UserID = userID
	f.SMSEnabled = enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&f).Error
	}
	return s.db.Save(&f).Error
}

// VerifySMSCode implements userauth.SMSCodeVerifier. Consumes the code on success if not expired.
func (s Store) VerifySMSCode(userID, code string) (bool, error) {
	hash := hashutil.HashCodeSHA256(code)
	var m smsVerificationCodeModel
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
