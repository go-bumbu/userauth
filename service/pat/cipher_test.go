package pat_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func TestAESGCMCipherRoundTrip(t *testing.T) {
	c, err := pat.NewAESGCMCipher(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCMCipher: %v", err)
	}
	ct, keyID, err := c.Encrypt("s3cret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if keyID != "k1" {
		t.Errorf("keyID = %q, want k1", keyID)
	}
	if strings.Contains(ct, "s3cret") {
		t.Error("ciphertext must not contain the plaintext")
	}
	got, err := c.Decrypt(ct, "k1")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("round-trip = %q, want s3cret", got)
	}
}

func TestAESGCMCipherRejectsUnknownKeyID(t *testing.T) {
	c, _ := pat.NewAESGCMCipher(testKey(), "k1")
	ct, _, _ := c.Encrypt("x")
	if _, err := c.Decrypt(ct, "other"); err == nil {
		t.Error("decrypt with unknown keyID should error")
	}
}

func TestAESGCMCipherValidation(t *testing.T) {
	if _, err := pat.NewAESGCMCipher([]byte("short"), "k1"); err == nil {
		t.Error("short key should error")
	}
	if _, err := pat.NewAESGCMCipher(testKey(), ""); err == nil {
		t.Error("empty keyID should error")
	}
}
