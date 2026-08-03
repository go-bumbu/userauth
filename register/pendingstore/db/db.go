// Package db provides a GORM-backed register.PendingStore. Pending
// registrations are stored server-side in the pending_registrations table,
// one row per login ID.
package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/register"
	"gorm.io/gorm"
)

// registrationModel stores one pending registration per login ID
// (pending_registrations table).
type registrationModel struct {
	gorm.Model
	LoginID    string `gorm:"uniqueIndex;not null"`
	PassHash   string
	Email      string
	InviteCode string
	Satisfied  string    // JSON-encoded []string of verified check IDs
	ExpiresAt  time.Time `gorm:"not null"`
}

func (registrationModel) TableName() string { return "pending_registrations" }

var ErrRegistrationNotFound = errors.New("no pending registration found")
var ErrRegistrationExpired = errors.New("pending registration expired")

// Store is a GORM-backed pending registration store.
type Store struct {
	db *gorm.DB
}

// New creates a Store and auto-migrates the pending_registrations table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&registrationModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Set stores the pending registration. Overwrites any existing entry.
func (s *Store) Set(_ *http.Request, _ http.ResponseWriter, reg register.Registration) error {
	satisfied, err := json.Marshal(reg.Satisfied)
	if err != nil {
		return fmt.Errorf("pending registration encode satisfied: %w", err)
	}
	var m registrationModel
	err = s.db.Where("login_id = ?", reg.LoginID).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.LoginID = reg.LoginID
	m.PassHash = reg.PassHash
	m.Email = reg.Email
	m.InviteCode = reg.InviteCode
	m.Satisfied = string(satisfied)
	m.ExpiresAt = reg.ExpiresAt
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// Get retrieves the pending registration for the login ID. Returns an error
// if not found or expired; an expired row is deleted.
func (s *Store) Get(_ *http.Request, loginID string) (register.Registration, error) {
	var m registrationModel
	err := s.db.Where("login_id = ?", loginID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return register.Registration{}, ErrRegistrationNotFound
		}
		return register.Registration{}, err
	}
	if time.Now().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return register.Registration{}, ErrRegistrationExpired
	}
	var satisfied []string
	if m.Satisfied != "" {
		if err := json.Unmarshal([]byte(m.Satisfied), &satisfied); err != nil {
			return register.Registration{}, fmt.Errorf("pending registration decode satisfied: %w", err)
		}
	}
	return register.Registration{
		LoginID:    m.LoginID,
		PassHash:   m.PassHash,
		Email:      m.Email,
		InviteCode: m.InviteCode,
		Satisfied:  satisfied,
		ExpiresAt:  m.ExpiresAt,
	}, nil
}

// Clear deletes the pending registration for the login ID.
func (s *Store) Clear(_ *http.Request, _ http.ResponseWriter, loginID string) error {
	return s.db.Where("login_id = ?", loginID).Delete(&registrationModel{}).Error
}
