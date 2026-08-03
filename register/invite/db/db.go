// Package db provides a GORM-backed invite.Store. Invites are stored in the
// invites table; Consume decrements the remaining uses with a single
// conditional UPDATE, so it is atomic without an explicit transaction.
package db

import (
	"errors"
	"time"

	"github.com/go-bumbu/userauth/register/invite"
	"gorm.io/gorm"
)

// inviteModel stores one invite per row (invites table).
type inviteModel struct {
	gorm.Model
	Code      string `gorm:"uniqueIndex;not null"`
	Note      string
	Email     string
	UsesLeft  int
	ExpiresAt time.Time // zero value means the invite never expires
	IssuedAt  time.Time
	Revoked   bool
}

func (inviteModel) TableName() string { return "invites" }

// Store is a GORM-backed invite store.
type Store struct {
	db *gorm.DB
}

// New creates a Store and auto-migrates the invites table.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(&inviteModel{}); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Save stores the invite. Overwrites any existing entry with the same code.
func (s *Store) Save(inv invite.Invite) error {
	var m inviteModel
	err := s.db.Where("code = ?", inv.Code).First(&m).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.Code = inv.Code
	m.Note = inv.Note
	m.Email = inv.Email
	m.UsesLeft = inv.UsesLeft
	m.ExpiresAt = inv.ExpiresAt
	m.IssuedAt = inv.CreatedAt
	m.Revoked = inv.Revoked
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&m).Error
	}
	return s.db.Save(&m).Error
}

// Get retrieves the invite by code.
func (s *Store) Get(code string) (invite.Invite, error) {
	var m inviteModel
	err := s.db.Where("code = ?", code).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return invite.Invite{}, invite.ErrInviteNotFound
		}
		return invite.Invite{}, err
	}
	return m.toInvite(), nil
}

// List returns all invites, including revoked and exhausted ones.
func (s *Store) List() ([]invite.Invite, error) {
	var rows []inviteModel
	if err := s.db.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]invite.Invite, 0, len(rows))
	for _, m := range rows {
		out = append(out, m.toInvite())
	}
	return out, nil
}

// Delete removes the invite by code.
func (s *Store) Delete(code string) error {
	return s.db.Where("code = ?", code).Delete(&inviteModel{}).Error
}

// Consume atomically decrements UsesLeft of a usable invite. The single
// conditional UPDATE makes the check-and-decrement atomic; RowsAffected
// reports whether a usable invite matched.
func (s *Store) Consume(code, email string) (bool, error) {
	res := s.db.Model(&inviteModel{}).
		Where("code = ? AND revoked = ? AND uses_left > 0", code, false).
		Where("expires_at = ? OR expires_at > ?", time.Time{}, time.Now()).
		Where("email = ? OR email = ?", "", email).
		Update("uses_left", gorm.Expr("uses_left - 1"))
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (m inviteModel) toInvite() invite.Invite {
	return invite.Invite{
		Code:      m.Code,
		Note:      m.Note,
		Email:     m.Email,
		UsesLeft:  m.UsesLeft,
		ExpiresAt: m.ExpiresAt,
		CreatedAt: m.IssuedAt,
		Revoked:   m.Revoked,
	}
}
