package userdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
	"gorm.io/gorm"
)

// PATStore returns the store's pat.TokenStore view. The indirection exists
// because Store.Delete is already taken by user deletion; the token-scoped
// delete is DeletePAT.
func (s Store) PATStore() pat.TokenStore { return patStore{s} }

// patStore adapts Store to pat.TokenStore.
type patStore struct{ s Store }

var _ pat.TokenStore = patStore{}

func (p patStore) Insert(rec pat.TokenRecord) error                { return p.s.InsertPAT(rec) }
func (p patStore) GetByTokenID(id string) (pat.TokenRecord, error) { return p.s.GetPATByTokenID(id) }
func (p patStore) ListByUser(userID string) ([]pat.TokenRecord, error) {
	return p.s.ListPATsByUser(userID)
}
func (p patStore) Delete(userID, tokenID string) error     { return p.s.DeletePAT(userID, tokenID) }
func (p patStore) Touch(tokenID string, t time.Time) error { return p.s.TouchPAT(tokenID, t) }

// InsertPAT stores a new token record; TokenID must be unique.
func (s Store) InsertPAT(rec pat.TokenRecord) error {
	m, err := toPatModel(rec)
	if err != nil {
		return err
	}
	return s.db.Create(&m).Error
}

// GetPATByTokenID returns the token record or pat.ErrTokenNotFound.
func (s Store) GetPATByTokenID(tokenID string) (pat.TokenRecord, error) {
	var m patModel
	err := s.db.First(&m, "token_id = ?", tokenID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return pat.TokenRecord{}, pat.ErrTokenNotFound
		}
		return pat.TokenRecord{}, err
	}
	return toPatRecord(m)
}

// ListPATsByUser returns the user's token records, oldest first.
func (s Store) ListPATsByUser(userID string) ([]pat.TokenRecord, error) {
	var rows []patModel
	if err := s.db.Where("user_id = ?", userID).
		Order("created_at ASC, token_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]pat.TokenRecord, 0, len(rows))
	for _, m := range rows {
		rec, err := toPatRecord(m)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// DeletePAT removes the token only when it belongs to userID; returns
// pat.ErrTokenNotFound for absent or foreign tokens.
func (s Store) DeletePAT(userID, tokenID string) error {
	res := s.db.Where("user_id = ? AND token_id = ?", userID, tokenID).Delete(&patModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return pat.ErrTokenNotFound
	}
	return nil
}

// TouchPAT updates the token's last-used timestamp.
func (s Store) TouchPAT(tokenID string, t time.Time) error {
	res := s.db.Model(&patModel{}).Where("token_id = ?", tokenID).
		Update("last_used_at", t)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return pat.ErrTokenNotFound
	}
	return nil
}

func toPatModel(rec pat.TokenRecord) (patModel, error) {
	scopes := ""
	if len(rec.Scopes) > 0 {
		b, err := json.Marshal(rec.Scopes)
		if err != nil {
			return patModel{}, fmt.Errorf("encode scopes: %w", err)
		}
		scopes = string(b)
	}
	return patModel{
		TokenID:    rec.TokenID,
		UserID:     rec.UserID,
		Name:       rec.Name,
		SecretHash: rec.SecretHash,
		Scopes:     scopes,
		ExpiresAt:  rec.ExpiresAt,
		LastUsedAt: rec.LastUsedAt,
		CreatedAt:  rec.CreatedAt,
	}, nil
}

func toPatRecord(m patModel) (pat.TokenRecord, error) {
	var scopes []string
	if m.Scopes != "" {
		if err := json.Unmarshal([]byte(m.Scopes), &scopes); err != nil {
			return pat.TokenRecord{}, fmt.Errorf("decode scopes: %w", err)
		}
	}
	return pat.TokenRecord{
		TokenID:    m.TokenID,
		UserID:     m.UserID,
		Name:       m.Name,
		SecretHash: m.SecretHash,
		Scopes:     scopes,
		ExpiresAt:  m.ExpiresAt,
		LastUsedAt: m.LastUsedAt,
		CreatedAt:  m.CreatedAt,
	}, nil
}
