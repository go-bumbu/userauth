// Package memory provides an in-memory login.AttemptStore.
package memory

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-bumbu/userauth/flow/login"
)

var ErrAttemptNotFound = errors.New("no login attempt found")
var ErrAttemptExpired = errors.New("login attempt expired")

// Store is an in-memory login attempt store. Safe for concurrent use.
// Suitable for development and testing, or for single-instance deployments.
type Store struct {
	mu    sync.Mutex
	store map[string]login.Attempt
}

func New() *Store {
	return &Store{
		store: make(map[string]login.Attempt),
	}
}

func (m *Store) Set(_ *http.Request, _ http.ResponseWriter, a login.Attempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[a.UserID] = a
	return nil
}

func (m *Store) Get(_ *http.Request, userID string) (login.Attempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.store[userID]
	if !ok {
		return login.Attempt{}, ErrAttemptNotFound
	}
	if time.Now().After(a.ExpiresAt) {
		delete(m.store, userID)
		return login.Attempt{}, ErrAttemptExpired
	}
	return a, nil
}

func (m *Store) Clear(_ *http.Request, _ http.ResponseWriter, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, userID)
	return nil
}
