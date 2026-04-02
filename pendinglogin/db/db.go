package db

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-bumbu/userauth/handlers/login"
	"gorm.io/gorm"
)

// pendingLoginModel stores one pending login per user (pending_logins table).
type pendingLoginModel struct {
	gorm.Model
	UserID         string `gorm:"uniqueIndex;not null"`
	KeepMeLoggedIn bool
	ExpiresAt      time.Time `gorm:"not null"`
}

func (pendingLoginModel) TableName() string { return "pending_logins" }

var ErrPendingLoginNotFound = errors.New("no pending login found")
var ErrPendingLoginExpired = errors.New("pending login expired")

// Store is a GORM-backed pending login store.
type Store struct {
	db *gorm.DB
}

// New creates a Store and auto-migrates the pending_logins table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&pendingLoginModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// SetPendingLogin stores a pending login for the user. Overwrites any existing entry.
func (s *Store) SetPendingLogin(_ *http.Request, _ http.ResponseWriter, data login.PendingLogin) error {
	var m pendingLoginModel
	err := s.db.Where("user_id = ?", data.UserID).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = data.UserID
	m.KeepMeLoggedIn = data.KeepMeLoggedIn
	m.ExpiresAt = data.ExpiresAt
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// GetPendingLogin retrieves the pending login for the user. Returns error if not found or expired.
func (s *Store) GetPendingLogin(_ *http.Request, userID string) (login.PendingLogin, error) {
	var m pendingLoginModel
	err := s.db.Where("user_id = ?", userID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return login.PendingLogin{}, ErrPendingLoginNotFound
		}
		return login.PendingLogin{}, err
	}
	if time.Now().After(m.ExpiresAt) {
		_ = s.db.Delete(&m).Error
		return login.PendingLogin{}, ErrPendingLoginExpired
	}
	return login.PendingLogin{
		UserID:         m.UserID,
		KeepMeLoggedIn: m.KeepMeLoggedIn,
		ExpiresAt:      m.ExpiresAt,
	}, nil
}

// ClearPendingLogin deletes the pending login for the user.
func (s *Store) ClearPendingLogin(_ *http.Request, _ http.ResponseWriter, userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&pendingLoginModel{}).Error
}
