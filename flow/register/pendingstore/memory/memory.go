// Package memory provides an in-memory register.PendingStore.
package memory

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-bumbu/userauth/flow/register"
)

var ErrRegistrationNotFound = errors.New("no pending registration found")
var ErrRegistrationExpired = errors.New("pending registration expired")

// Store is an in-memory pending registration store. Safe for concurrent use.
// Suitable for development and testing, or for single-instance deployments.
type Store struct {
	mu    sync.Mutex
	store map[string]register.Registration
}

func New() *Store {
	return &Store{
		store: make(map[string]register.Registration),
	}
}

func (m *Store) Set(_ *http.Request, _ http.ResponseWriter, reg register.Registration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[reg.LoginID] = reg
	return nil
}

func (m *Store) Get(_ *http.Request, loginID string) (register.Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	reg, ok := m.store[loginID]
	if !ok {
		return register.Registration{}, ErrRegistrationNotFound
	}
	if time.Now().After(reg.ExpiresAt) {
		delete(m.store, loginID)
		return register.Registration{}, ErrRegistrationExpired
	}
	return reg, nil
}

func (m *Store) Clear(_ *http.Request, _ http.ResponseWriter, loginID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, loginID)
	return nil
}
