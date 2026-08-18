package memory

import (
	"sync"
	"time"
)

type codeEntry struct {
	hash      string
	expiresAt time.Time
	attempts  int
}

// Store is an in-memory CodeStore. Safe for concurrent use. One Store instance
// backs one code channel (e.g. email or SMS).
type Store struct {
	mu    sync.Mutex
	codes map[string]codeEntry
}

func New() *Store {
	return &Store{codes: make(map[string]codeEntry)}
}

// StoreCode saves the hash for userID, replacing any previous code.
func (s *Store) StoreCode(userID, hash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[userID] = codeEntry{hash: hash, expiresAt: expiresAt}
	return nil
}

// ConsumeCode atomically checks for a non-expired matching hash and deletes it
// on success (one-time use). Returns false if absent, expired, or mismatched.
// Each mismatch counts as a failed attempt; reaching maxAttempts deletes the
// code.
func (s *Store) ConsumeCode(userID, hash string, maxAttempts int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.codes[userID]
	if !ok {
		return false, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.codes, userID)
		return false, nil
	}
	if entry.hash != hash {
		entry.attempts++
		if entry.attempts >= maxAttempts {
			delete(s.codes, userID)
		} else {
			s.codes[userID] = entry
		}
		return false, nil
	}
	delete(s.codes, userID)
	return true, nil
}

// PurgeUser deletes the user's outstanding codes on every channel — not only
// this Store's channel (which the memory implementation does not track), so one
// purger wired into a user store's cascade covers them all. It satisfies
// userdb.UserPurger.
func (s *Store) PurgeUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, userID)
	return nil
}
