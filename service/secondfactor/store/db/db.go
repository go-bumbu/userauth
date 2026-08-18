// Package db provides a GORM-backed secondfactor.Store. Flags live in the
// user_second_factor_flags table, one row per user and factor, and this package owns
// the model and its auto-migration.
//
// The factor is a column rather than a boolean per kind, so adding a factor is
// a wiring change instead of a schema migration.
package db

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/secondfactor"
	"gorm.io/gorm"
)

// flagModel stores one user's preference for one factor (user_second_factor_flags
// table, UserID = the user's canonical ID). Factor holds the
// userauth.SecondFactor label.
type flagModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index:idx_user_second_factor_flags_user_factor,unique;not null"`
	Factor    string `gorm:"index:idx_user_second_factor_flags_user_factor,unique;not null"`
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (flagModel) TableName() string { return "user_second_factor_flags" }

// Store is a GORM-backed secondfactor.Store.
type Store struct {
	db *gorm.DB
}

var _ secondfactor.Store = (*Store)(nil)

// New creates a Store and auto-migrates the user_second_factor_flags table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&flagModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Enabled reports whether the user turned the factor on; no row means off.
func (s *Store) Enabled(userID string, factor userauth.SecondFactor) (bool, error) {
	var m flagModel
	err := s.db.Where("user_id = ? AND factor = ?", userID, string(factor)).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return m.Enabled, nil
}

// SetEnabled turns the factor on or off, updating the existing row when there
// is one so the unique (user, factor) pair is never duplicated.
func (s *Store) SetEnabled(userID string, factor userauth.SecondFactor, enabled bool) error {
	var m flagModel
	err := s.db.Where("user_id = ? AND factor = ?", userID, string(factor)).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = userID
	m.Factor = string(factor)
	m.Enabled = enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// PurgeUser deletes every flag the user has, so a user store's delete can
// cascade here. It satisfies userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&flagModel{}).Error
}
