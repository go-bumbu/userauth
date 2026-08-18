// Package memory is an in-memory secondfactor.Store, for tests and
// single-process deployments that do not need the preference to survive a
// restart.
package memory

import (
	"sync"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/secondfactor"
)

type flagKey struct {
	userID string
	factor userauth.SecondFactor
}

// Store keeps one flag per user and factor in a map. Safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	flags map[flagKey]bool
}

var _ secondfactor.Store = (*Store)(nil)

func New() *Store {
	return &Store{flags: make(map[flagKey]bool)}
}

// Enabled reports whether the user turned the factor on; an unset flag is off.
func (s *Store) Enabled(userID string, factor userauth.SecondFactor) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.flags[flagKey{userID, factor}], nil
}

// SetEnabled turns the factor on or off for the user.
func (s *Store) SetEnabled(userID string, factor userauth.SecondFactor, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags[flagKey{userID, factor}] = enabled
	return nil
}
