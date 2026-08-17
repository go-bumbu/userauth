package userdb

import (
	"errors"

	"github.com/go-bumbu/userauth/service/totp"
	"gorm.io/gorm"
)

// TOTPStore returns the store's totp.Store view. Persistence only: the secret
// is stored exactly as service/totp hands it over (encrypted, when that service
// has a cipher configured), and this store never generates or validates
// anything.
//
// The indirection exists because the method names on the totp.Store interface
// (Get/Set/Delete) are far too generic for a user store, whose Delete already
// means "delete the user".
func (s Store) TOTPStore() totp.Store { return totpStore{s} }

// totpStore adapts Store to totp.Store.
type totpStore struct{ s Store }

var _ totp.Store = totpStore{}

// Get returns the user's TOTP record or totp.ErrNotEnrolled.
func (t totpStore) Get(userID string) (totp.Record, error) {
	var m totpModel
	err := t.s.db.First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return totp.Record{}, totp.ErrNotEnrolled
		}
		return totp.Record{}, err
	}
	return totp.Record{Secret: m.Secret, KeyID: m.KeyID, Enabled: m.Enabled}, nil
}

// Set stores the record, replacing any previous one for the user.
func (t totpStore) Set(userID string, rec totp.Record) error {
	var m totpModel
	err := t.s.db.First(&m, "user_id = ?", userID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = userID
	m.Secret = rec.Secret
	m.KeyID = rec.KeyID
	m.Enabled = rec.Enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return t.s.db.Create(&m).Error
	}
	return t.s.db.Save(&m).Error
}

// Delete removes the user's record; deleting an absent one is not an error.
func (t totpStore) Delete(userID string) error {
	return t.s.db.Where("user_id = ?", userID).Delete(&totpModel{}).Error
}

// totpEnabled reports whether the user has a confirmed TOTP factor, reading
// only the flag (used by AvailableSecondFactors). It deliberately does not
// touch the secret: answering "is this factor available" must not need the
// decryption key.
func (s Store) totpEnabled(userID string) (bool, error) {
	var m totpModel
	err := s.db.Select("enabled").First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return m.Enabled, nil
}
