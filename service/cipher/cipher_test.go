package cipher_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/service/cipher"
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func TestAESGCMRoundTrip(t *testing.T) {
	c, err := cipher.NewAESGCM(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	ct, keyID, err := c.Encrypt("s3cret", "ctx")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if keyID != "k1" {
		t.Errorf("keyID = %q, want k1", keyID)
	}
	if strings.Contains(ct, "s3cret") {
		t.Error("ciphertext must not contain the plaintext")
	}
	got, err := c.Decrypt(ct, "k1", "ctx")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("round-trip = %q, want s3cret", got)
	}
}

func TestAESGCMRejectsUnknownKeyID(t *testing.T) {
	c, _ := cipher.NewAESGCM(testKey(), "k1")
	ct, _, _ := c.Encrypt("x", "ctx")
	if _, err := c.Decrypt(ct, "other", "ctx"); err == nil {
		t.Error("decrypt with unknown keyID should error")
	}
}

func TestAESGCMContextBinding(t *testing.T) {
	c, _ := cipher.NewAESGCM(testKey(), "k1")
	ct, _, err := c.Encrypt("secret", "tokenABC")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// correct context succeeds
	got, err := c.Decrypt(ct, "k1", "tokenABC")
	if err != nil {
		t.Fatalf("Decrypt with correct context: %v", err)
	}
	if got != "secret" {
		t.Errorf("decrypted = %q, want secret", got)
	}
	// wrong context fails
	if _, err := c.Decrypt(ct, "k1", "tokenXYZ"); err == nil {
		t.Error("Decrypt with wrong context should fail")
	}
}

// TestAESGCMEmptyContextIsUnbound documents that an empty context means "no
// AAD binding": ciphertexts written before the cipher took a context parameter
// (nil AAD) stay decryptable. service/totp relies on this for TOTP secrets
// encrypted by the old userdb code path.
func TestAESGCMEmptyContextIsUnbound(t *testing.T) {
	c, _ := cipher.NewAESGCM(testKey(), "k1")
	ct, _, err := c.Encrypt("secret", "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(ct, "k1", "")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "secret" {
		t.Errorf("decrypted = %q, want secret", got)
	}
}

func TestAESGCMValidation(t *testing.T) {
	if _, err := cipher.NewAESGCM([]byte("short"), "k1"); err == nil {
		t.Error("short key should error")
	}
	if _, err := cipher.NewAESGCM(testKey(), ""); err == nil {
		t.Error("empty keyID should error")
	}
}
