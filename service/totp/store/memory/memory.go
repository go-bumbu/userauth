// Package memory is an in-memory totp.Store, for tests and single-process
// deployments that do not need enrolments to survive a restart.
package memory

import (
	"sync"

	"github.com/go-bumbu/userauth/service/totp"
)

// Store keeps one TOTP record per user in a map. Safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	records map[string]totp.Record
}

var _ totp.Store = (*Store)(nil)

func New() *Store {
	return &Store{records: make(map[string]totp.Record)}
}

// Get returns the user's record or totp.ErrNotEnrolled.
func (s *Store) Get(userID string) (totp.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[userID]
	if !ok {
		return totp.Record{}, totp.ErrNotEnrolled
	}
	return rec, nil
}

// Set stores the record, replacing any previous one for the user.
func (s *Store) Set(userID string, rec totp.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[userID] = rec
	return nil
}

// Delete removes the record; deleting an absent record is not an error.
func (s *Store) Delete(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, userID)
	return nil
}

// PurgeUser deletes the user's TOTP enrolment. It satisfies
// userdb.UserPurger so this store can join a user-delete cascade.
func (s *Store) PurgeUser(userID string) error {
	return s.Delete(userID)
}
