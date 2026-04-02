package memory

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-bumbu/userauth/handlers/login"
)

var ErrPendingLoginNotFound = errors.New("no pending login found")
var ErrPendingLoginExpired = errors.New("pending login expired")

// Store is an in-memory pending login store. Safe for concurrent use.
// Suitable for development and testing, or when paired with staticusers.
type Store struct {
	mu    sync.Mutex
	store map[string]login.PendingLogin
}

func New() *Store {
	return &Store{
		store: make(map[string]login.PendingLogin),
	}
}

func (m *Store) SetPendingLogin(_ *http.Request, _ http.ResponseWriter, data login.PendingLogin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[data.UserID] = data
	return nil
}

func (m *Store) GetPendingLogin(_ *http.Request, userID string) (login.PendingLogin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.store[userID]
	if !ok {
		return login.PendingLogin{}, ErrPendingLoginNotFound
	}
	if time.Now().After(data.ExpiresAt) {
		delete(m.store, userID)
		return login.PendingLogin{}, ErrPendingLoginExpired
	}
	return data, nil
}

func (m *Store) ClearPendingLogin(_ *http.Request, _ http.ResponseWriter, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, userID)
	return nil
}
