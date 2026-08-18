// Package db provides a GORM-backed totp.Store. The secret and its enabled
// flag live in the user_totp table, one row per user, and this package owns the
// model and its auto-migration — a setup that offers no authenticator factor
// never creates the table.
//
// Persistence only: the secret is stored exactly as service/totp hands it over
// (ciphertext when that service has a cipher configured), and this store never
// generates, encrypts or validates anything.
package db

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth/service/secondfactor"
	"github.com/go-bumbu/userauth/service/totp"
	"gorm.io/gorm"
)

// totpModel stores the TOTP secret and enabled flag per user (user_totp table,
// UserID = the user's canonical ID). Secret is opaque here: service/totp decides
// whether it holds the base32 secret or its ciphertext, and KeyID names the
// cipher key that produced it (empty for secrets stored in the clear, and for
// rows written before this column existed — service/totp treats those as "the
// current key"). Enabled is false while an enrolment awaits its first confirmed
// code.
type totpModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"uniqueIndex;not null"`
	Secret    string `gorm:"not null"`
	KeyID     string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (totpModel) TableName() string { return "user_totp" }

// Store is a GORM-backed totp.Store.
type Store struct {
	db *gorm.DB
}

var _ totp.Store = (*Store)(nil)
var _ secondfactor.Availability = (*Store)(nil)

// New creates a Store and auto-migrates the user_totp table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&totpModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Get returns the user's record or totp.ErrNotEnrolled.
func (s *Store) Get(userID string) (totp.Record, error) {
	var m totpModel
	err := s.db.First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return totp.Record{}, totp.ErrNotEnrolled
		}
		return totp.Record{}, err
	}
	return totp.Record{Secret: m.Secret, KeyID: m.KeyID, Enabled: m.Enabled}, nil
}

// Set stores the record, replacing any previous one for the user.
func (s *Store) Set(userID string, rec totp.Record) error {
	var m totpModel
	err := s.db.First(&m, "user_id = ?", userID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = userID
	m.Secret = rec.Secret
	m.KeyID = rec.KeyID
	m.Enabled = rec.Enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// Delete removes the user's record; deleting an absent one is not an error.
func (s *Store) Delete(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&totpModel{}).Error
}

// Available reports whether the user has a confirmed authenticator factor. It
// reads only the enabled column: answering "is this factor available" must not
// need the decryption key. It satisfies secondfactor.Availability.
func (s *Store) Available(userID string) (bool, error) {
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

// PurgeUser deletes the user's enrolment, so a user store's delete can cascade
// here. It satisfies userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	return s.Delete(userID)
}
