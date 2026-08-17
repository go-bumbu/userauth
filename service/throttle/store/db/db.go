// Package db provides a GORM-backed throttle.Store. Failure state is
// stored in the login_throttle table, one row per user and method; it owns
// its own model and auto-migration, independent from userdb.
package db

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// throttleModel stores consecutive wrong-guess state per user and method
// (login_throttle table).
type throttleModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index:idx_throttle_user_method,unique;not null"`
	Method    string `gorm:"index:idx_throttle_user_method,unique;not null"`
	Count     int    `gorm:"not null"`
	LastAt    time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (throttleModel) TableName() string { return "login_throttle" }

// Store is a GORM-backed throttle store.
type Store struct {
	db *gorm.DB
}

// New creates a Store and auto-migrates the login_throttle table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&throttleModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Failures returns the consecutive failure count and last failure time.
func (s *Store) Failures(userID, method string) (int, time.Time, error) {
	var m throttleModel
	err := s.db.Where("user_id = ? AND method = ?", userID, method).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, time.Time{}, nil
		}
		return 0, time.Time{}, err
	}
	return m.Count, m.LastAt, nil
}

// AddFailure increments the failure count and records the failure time.
func (s *Store) AddFailure(userID, method string, at time.Time) error {
	var m throttleModel
	err := s.db.Where("user_id = ? AND method = ?", userID, method).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = userID
	m.Method = method
	m.Count++
	m.LastAt = at
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// Clear removes the failure state for the user and method.
func (s *Store) Clear(userID, method string) error {
	return s.db.Where("user_id = ? AND method = ?", userID, method).Delete(&throttleModel{}).Error
}
