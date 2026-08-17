package pat

import (
	"github.com/go-bumbu/userauth/service/cipher"
)

// SecretCipher encrypts token secrets for recoverable storage; alias of
// service/cipher.Secret, which is shared with service/totp. The library never
// manages keys: the consuming application decides where keys live and injects
// an implementation via Opts.Cipher.
type SecretCipher = cipher.Secret

// AESGCMCipher is a single-key AES-256-GCM SecretCipher; alias of
// service/cipher.AESGCM.
type AESGCMCipher = cipher.AESGCM

// NewAESGCMCipher wraps a 32-byte AES-256 key under the given key id.
func NewAESGCMCipher(key []byte, keyID string) (*AESGCMCipher, error) {
	return cipher.NewAESGCM(key, keyID)
}
