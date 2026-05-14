package memory

import (
	"sync"
	"time"

	"github.com/go-bumbu/userauth/hashutil"
)

type codeEntry struct {
	hash      string
	expiresAt time.Time
}

// Store is an in-memory verification code store. Safe for concurrent use.
// Suitable for file-mode email 2FA where codes are transient.
type Store struct {
	mu    sync.Mutex
	codes map[string]codeEntry
}

func New() *Store {
	return &Store{
		codes: make(map[string]codeEntry),
	}
}

// Store saves a hashed code for the given user, replacing any previous code.
// This signature matches the Store func field on userauth.VerificationCodeService.
func (s *Store) Store(userID, hash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[userID] = codeEntry{hash: hash, expiresAt: expiresAt}
	return nil
}

// VerifyEmailCode implements userauth.EmailCodeVerifier.
// Returns true if the code matches and has not expired, then deletes the entry.
func (s *Store) VerifyEmailCode(userID, code string) (bool, error) {
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
	if hashutil.HashCodeSHA256(code) != entry.hash {
		return false, nil
	}
	delete(s.codes, userID)
	return true, nil
}
