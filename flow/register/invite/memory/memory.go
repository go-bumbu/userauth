// Package memory provides an in-memory invite.Store. Safe for concurrent
// use. Suitable for development and testing, or for single-instance
// deployments.
package memory

import (
	"sync"
	"time"

	"github.com/go-bumbu/userauth/flow/register/invite"
)

// Store is an in-memory invite store.
type Store struct {
	mu    sync.Mutex
	store map[string]invite.Invite
}

func New() *Store {
	return &Store{store: make(map[string]invite.Invite)}
}

func (m *Store) Save(inv invite.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[inv.Code] = inv
	return nil
}

func (m *Store) Get(code string) (invite.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.store[code]
	if !ok {
		return invite.Invite{}, invite.ErrInviteNotFound
	}
	return inv, nil
}

func (m *Store) List() ([]invite.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]invite.Invite, 0, len(m.store))
	for _, inv := range m.store {
		out = append(out, inv)
	}
	return out, nil
}

func (m *Store) Delete(code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, code)
	return nil
}

// Consume atomically decrements UsesLeft of a usable invite; the mutex makes
// the check-and-decrement atomic.
func (m *Store) Consume(code, email string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.store[code]
	if !ok || !inv.Usable(email, time.Now()) {
		return false, nil
	}
	inv.UsesLeft--
	m.store[code] = inv
	return true, nil
}
