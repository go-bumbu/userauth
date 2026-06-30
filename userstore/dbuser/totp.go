package dbuser

import (
	"errors"
	"fmt"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/hashutil"
	"gorm.io/gorm"
)

// GetTOTP implements userauth.TOTPGetter. Decrypts the secret if an encryption key is configured.
func (s Store) GetTOTP(userID string) (userauth.TOTPData, error) {
	var m totpModel
	err := s.db.First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.TOTPData{Enabled: false}, nil
		}
		return userauth.TOTPData{}, err
	}
	secret := m.Secret
	if s.totpEncKey != nil && secret != "" {
		decrypted, err := hashutil.Decrypt(secret, s.totpEncKey)
		if err != nil {
			return userauth.TOTPData{}, fmt.Errorf("decrypt TOTP secret: %w", err)
		}
		secret = decrypted
	}
	return userauth.TOTPData{
		Enabled: m.Enabled,
		Secret:  secret,
	}, nil
}

// SetTOTP is a store method for configuring TOTP. Encrypts the secret if an encryption key is configured.
func (s Store) SetTOTP(userID string, data userauth.TOTPData) error {
	var m totpModel
	err := s.db.First(&m, "user_id = ?", userID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	secret := data.Secret
	if s.totpEncKey != nil && secret != "" {
		encrypted, encErr := hashutil.Encrypt(secret, s.totpEncKey)
		if encErr != nil {
			return fmt.Errorf("encrypt TOTP secret: %w", encErr)
		}
		secret = encrypted
	}
	m.UserID = userID
	m.Secret = secret
	m.Enabled = data.Enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}
