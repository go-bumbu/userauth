// Package memory is an in-memory recoverycodes.Store, for tests and
// single-process deployments that do not need codes to survive a restart.
package memory

import (
	"slices"
	"sync"

	"github.com/go-bumbu/userauth/service/recoverycodes"
)

// Store keeps the unused code hashes per user. Safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	hashes map[string][]string
}

var _ recoverycodes.Store = (*Store)(nil)

func New() *Store {
	return &Store{hashes: make(map[string][]string)}
}

// Replace drops every hash the user has and stores the given ones.
func (s *Store) Replace(userID string, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(hashes) == 0 {
		delete(s.hashes, userID)
		return nil
	}
	s.hashes[userID] = slices.Clone(hashes)
	return nil
}

// Hashes returns the user's unused code hashes.
func (s *Store) Hashes(userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.hashes[userID]), nil
}

// Delete removes one hash; deleting an absent one is not an error.
func (s *Store) Delete(userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	left := slices.DeleteFunc(s.hashes[userID], func(h string) bool { return h == hash })
	if len(left) == 0 {
		delete(s.hashes, userID)
		return nil
	}
	s.hashes[userID] = left
	return nil
}

// Count returns how many unused codes the user has.
func (s *Store) Count(userID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.hashes[userID]), nil
}
