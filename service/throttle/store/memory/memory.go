// Package memory provides an in-memory throttle.Store for development
// and testing. State is per-instance and lost on restart; multi-instance
// deployments should use the db store.
package memory

import (
	"sync"
	"time"
)

type failState struct {
	count int
	last  time.Time
}

// Store is an in-memory ThrottleStore. Safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	fails map[string]failState
}

func New() *Store {
	return &Store{fails: make(map[string]failState)}
}

func key(userID, method string) string { return userID + "\x00" + method }

// Failures returns the consecutive failure count and last failure time.
func (s *Store) Failures(userID, method string) (int, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[key(userID, method)]
	return f.count, f.last, nil
}

// AddFailure increments the failure count and records the failure time.
func (s *Store) AddFailure(userID, method string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(userID, method)
	f := s.fails[k]
	f.count++
	f.last = at
	s.fails[k] = f
	return nil
}

// Clear removes the failure state for the user and method.
func (s *Store) Clear(userID, method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fails, key(userID, method))
	return nil
}
