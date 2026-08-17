// Package cipher provides symmetric encryption for credential secrets that
// must be recoverable at verify time (personal access tokens, TOTP secrets).
// The library never manages keys: the consuming application decides where keys
// live and injects an implementation. It is consumed by service/pat and
// service/totp.
package cipher

import (
	"fmt"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// Secret encrypts and decrypts credential secrets. KeyID identifies which key
// produced a ciphertext so implementations can rotate keys (new key encrypts,
// old keys stay decrypt-only). The context parameter binds the ciphertext to
// its record (AEAD additional authenticated data or KMS encryption context);
// the same value must be presented at decrypt time, and implementations must
// fail on mismatch.
type Secret interface {
	Encrypt(plaintext, context string) (ciphertext, keyID string, err error)
	Decrypt(ciphertext, keyID, context string) (string, error)
}

// AESGCM is a single-key AES-256-GCM Secret. Rotation across multiple keys is
// the consumer's concern; this implementation refuses ciphertexts from any
// other key.
type AESGCM struct {
	key   []byte
	keyID string
}

var _ Secret = (*AESGCM)(nil)

// NewAESGCM wraps a 32-byte AES-256 key under the given key id.
func NewAESGCM(key []byte, keyID string) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cipher: key must be 32 bytes, got %d", len(key))
	}
	if keyID == "" {
		return nil, fmt.Errorf("cipher: keyID is required")
	}
	k := make([]byte, 32)
	copy(k, key)
	return &AESGCM{key: k, keyID: keyID}, nil
}

// Encrypt encrypts the plaintext with the given context and reports the key id used.
func (c *AESGCM) Encrypt(plaintext, context string) (string, string, error) {
	ct, err := hashutil.Encrypt(plaintext, c.key, aad(context))
	if err != nil {
		return "", "", fmt.Errorf("cipher: encrypt: %w", err)
	}
	return ct, c.keyID, nil
}

// Decrypt decrypts a ciphertext previously produced under keyID with the given
// context. An empty keyID means the ciphertext predates key ids (written before
// its store had a key-id column) and is tried against this key; GCM
// authentication still rejects it if it was produced by a different key.
func (c *AESGCM) Decrypt(ciphertext, keyID, context string) (string, error) {
	if keyID != "" && keyID != c.keyID {
		return "", fmt.Errorf("cipher: unknown key id %q", keyID)
	}
	pt, err := hashutil.Decrypt(ciphertext, c.key, aad(context))
	if err != nil {
		return "", fmt.Errorf("cipher: decrypt: %w", err)
	}
	return pt, nil
}

// aad maps an empty context to a nil additional-authenticated-data slice.
// GCM treats nil and zero-length AAD identically, so this is only about being
// explicit that "no context" means "no binding".
func aad(context string) []byte {
	if context == "" {
		return nil
	}
	return []byte(context)
}
