package pat

import (
	"fmt"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// SecretCipher encrypts token secrets for recoverable storage. The library
// never manages keys: the consuming application decides where keys live and
// injects an implementation via Opts.Cipher. KeyID identifies which key
// produced a ciphertext so implementations can rotate keys (new key encrypts,
// old keys stay decrypt-only). The context parameter binds the ciphertext to
// its record (AEAD additional authenticated data or KMS encryption context);
// the same value must be presented at decrypt time, and implementations must
// fail on mismatch.
type SecretCipher interface {
	Encrypt(plaintext, context string) (ciphertext, keyID string, err error)
	Decrypt(ciphertext, keyID, context string) (string, error)
}

// AESGCMCipher is a single-key AES-256-GCM SecretCipher. Rotation across
// multiple keys is the consumer's concern; this implementation refuses
// ciphertexts from any other key.
type AESGCMCipher struct {
	key   []byte
	keyID string
}

var _ SecretCipher = (*AESGCMCipher)(nil)

// NewAESGCMCipher wraps a 32-byte AES-256 key under the given key id.
func NewAESGCMCipher(key []byte, keyID string) (*AESGCMCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pat: cipher key must be 32 bytes, got %d", len(key))
	}
	if keyID == "" {
		return nil, fmt.Errorf("pat: cipher keyID is required")
	}
	k := make([]byte, 32)
	copy(k, key)
	return &AESGCMCipher{key: k, keyID: keyID}, nil
}

// Encrypt encrypts the plaintext with the given context and reports the key id used.
func (c *AESGCMCipher) Encrypt(plaintext, context string) (string, string, error) {
	ct, err := hashutil.Encrypt(plaintext, c.key, []byte(context))
	if err != nil {
		return "", "", fmt.Errorf("pat: encrypt: %w", err)
	}
	return ct, c.keyID, nil
}

// Decrypt decrypts a ciphertext previously produced under keyID with the given context.
func (c *AESGCMCipher) Decrypt(ciphertext, keyID, context string) (string, error) {
	if keyID != c.keyID {
		return "", fmt.Errorf("pat: unknown cipher key id %q", keyID)
	}
	pt, err := hashutil.Decrypt(ciphertext, c.key, []byte(context))
	if err != nil {
		return "", fmt.Errorf("pat: decrypt: %w", err)
	}
	return pt, nil
}
