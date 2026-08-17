package pat_test

import (
	"bytes"
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// TestAESGCMCipherAlias checks the pat aliases still resolve to a working
// cipher; the cipher itself is covered in service/cipher.
func TestAESGCMCipherAlias(t *testing.T) {
	var c pat.SecretCipher
	c, err := pat.NewAESGCMCipher(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCMCipher: %v", err)
	}
	ct, keyID, err := c.Encrypt("s3cret", "tok1")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(ct, keyID, "tok1")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("round-trip = %q, want s3cret", got)
	}
}
