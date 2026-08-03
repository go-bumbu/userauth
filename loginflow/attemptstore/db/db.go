// Package db provides a GORM-backed loginflow.AttemptStore. Attempts are
// stored server-side in the login_attempts table, one row per user.
package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/loginflow"
	"gorm.io/gorm"
)

// attemptModel stores one login attempt per user (login_attempts table).
type attemptModel struct {
	gorm.Model
	UserID              string `gorm:"uniqueIndex;not null"`
	Satisfied           string // JSON-encoded []string of verified method IDs
	SessionKeepLoggedIn bool
	ExpiresAt           time.Time `gorm:"not null"`
}

func (attemptModel) TableName() string { return "login_attempts" }

var ErrAttemptNotFound = errors.New("no login attempt found")
var ErrAttemptExpired = errors.New("login attempt expired")

// Store is a GORM-backed login attempt store.
type Store struct {
	db *gorm.DB
}

// New creates a Store and auto-migrates the login_attempts table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&attemptModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Set stores the login attempt for the user. Overwrites any existing entry.
func (s *Store) Set(_ *http.Request, _ http.ResponseWriter, a loginflow.Attempt) error {
	satisfied, err := json.Marshal(a.Satisfied)
	if err != nil {
		return fmt.Errorf("login attempt encode satisfied: %w", err)
	}
	var m attemptModel
	err = s.db.Where("user_id = ?", a.UserID).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = a.UserID
	m.Satisfied = string(satisfied)
	m.SessionKeepLoggedIn = a.SessionKeepLoggedIn
	m.ExpiresAt = a.ExpiresAt
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// Get retrieves the login attempt for the user. Returns an error if not found
// or expired; an expired row is deleted.
func (s *Store) Get(_ *http.Request, userID string) (loginflow.Attempt, error) {
	var m attemptModel
	err := s.db.Where("user_id = ?", userID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return loginflow.Attempt{}, ErrAttemptNotFound
		}
		return loginflow.Attempt{}, err
	}
	if time.Now().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return loginflow.Attempt{}, ErrAttemptExpired
	}
	var satisfied []string
	if m.Satisfied != "" {
		if err := json.Unmarshal([]byte(m.Satisfied), &satisfied); err != nil {
			return loginflow.Attempt{}, fmt.Errorf("login attempt decode satisfied: %w", err)
		}
	}
	return loginflow.Attempt{
		UserID:              m.UserID,
		Satisfied:           satisfied,
		ExpiresAt:           m.ExpiresAt,
		SessionKeepLoggedIn: m.SessionKeepLoggedIn,
	}, nil
}

// Clear deletes the login attempt for the user.
func (s *Store) Clear(_ *http.Request, _ http.ResponseWriter, userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&attemptModel{}).Error
}
