// Package memory provides an in-memory pat.TokenStore for tests, demos, and
// applications that do not use a database. Safe for concurrent use.
package memory

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
)

// Store is an in-memory pat.TokenStore keyed by TokenID.
type Store struct {
	mu   sync.Mutex
	recs map[string]pat.TokenRecord
}

var _ pat.TokenStore = (*Store)(nil)

func New() *Store {
	return &Store{recs: make(map[string]pat.TokenRecord)}
}

// Insert stores a new record; the TokenID must be unique.
func (s *Store) Insert(rec pat.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.recs[rec.TokenID]; exists {
		return fmt.Errorf("token ID %q already exists", rec.TokenID)
	}
	s.recs[rec.TokenID] = rec
	return nil
}

// GetByTokenID returns the record or pat.ErrTokenNotFound.
func (s *Store) GetByTokenID(tokenID string) (pat.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[tokenID]
	if !ok {
		return pat.TokenRecord{}, pat.ErrTokenNotFound
	}
	return rec, nil
}

// ListByUser returns the user's records, oldest first.
func (s *Store) ListByUser(userID string) ([]pat.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pat.TokenRecord
	for _, rec := range s.recs {
		if rec.UserID == userID {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].TokenID < out[j].TokenID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Delete removes the record only when it belongs to userID.
func (s *Store) Delete(userID, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[tokenID]
	if !ok || rec.UserID != userID {
		return pat.ErrTokenNotFound
	}
	delete(s.recs, tokenID)
	return nil
}

// Touch updates LastUsedAt for the record.
func (s *Store) Touch(tokenID string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[tokenID]
	if !ok {
		return pat.ErrTokenNotFound
	}
	rec.LastUsedAt = &t
	s.recs[tokenID] = rec
	return nil
}

// PurgeUser deletes all the user's personal access tokens. It satisfies
// userdb.UserPurger so this store can join a user-delete cascade.
func (s *Store) PurgeUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tokenID, rec := range s.recs {
		if rec.UserID == userID {
			delete(s.recs, tokenID)
		}
	}
	return nil
}
