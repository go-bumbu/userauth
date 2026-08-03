package hashutil

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := "JBSWY3DPEHPK3PXP"
	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == plaintext {
		t.Error("encrypted should differ from plaintext")
	}
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	e1, _ := Encrypt("secret", key)
	e2, _ := Encrypt("secret", key)
	if e1 == e2 {
		t.Error("same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}
	encrypted, _ := Encrypt("secret", key1)
	_, err := Decrypt(encrypted, key2)
	if err == nil {
		t.Error("decrypting with wrong key should fail")
	}
}

func TestEncryptBadKeyLength(t *testing.T) {
	_, err := Encrypt("x", []byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestDecryptBadKeyLength(t *testing.T) {
	_, err := Decrypt("x", []byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}
}
