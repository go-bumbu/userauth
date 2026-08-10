package hashutil

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := "JBSWY3DPEHPK3PXP"
	encrypted, err := Encrypt(plaintext, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == plaintext {
		t.Error("encrypted should differ from plaintext")
	}
	decrypted, err := Decrypt(encrypted, key, nil)
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
	e1, _ := Encrypt("secret", key, nil)
	e2, _ := Encrypt("secret", key, nil)
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
	encrypted, _ := Encrypt("secret", key1, nil)
	_, err := Decrypt(encrypted, key2, nil)
	if err == nil {
		t.Error("decrypting with wrong key should fail")
	}
}

func TestEncryptBadKeyLength(t *testing.T) {
	_, err := Encrypt("x", []byte("short"), nil)
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestDecryptBadKeyLength(t *testing.T) {
	_, err := Decrypt("x", []byte("short"), nil)
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestEncryptKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{name: "empty key", keyLen: 0, wantErr: true},
		{name: "16 bytes (AES-128, rejected)", keyLen: 16, wantErr: true},
		{name: "24 bytes (AES-192, rejected)", keyLen: 24, wantErr: true},
		{name: "31 bytes", keyLen: 31, wantErr: true},
		{name: "32 bytes (AES-256)", keyLen: 32, wantErr: false},
		{name: "33 bytes", keyLen: 33, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			_, err := Encrypt("payload", key, nil)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Encrypt with %d-byte key: err = %v, wantErr = %v", tc.keyLen, err, tc.wantErr)
			}
		})
	}
}

func TestDecryptBadInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		encoded string
	}{
		{name: "not base64", encoded: "%%% not base64 %%%"},
		{name: "empty input", encoded: ""},
		// base64 of "short" (5 bytes) is shorter than the 12-byte GCM nonce
		{name: "shorter than nonce", encoded: base64.StdEncoding.EncodeToString([]byte("short"))},
		// valid length but garbage content fails GCM authentication
		{name: "corrupt ciphertext", encoded: base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(tc.encoded, key, nil); err == nil {
				t.Errorf("Decrypt(%q) should fail", tc.encoded)
			}
		})
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt("secret", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := Decrypt(tampered, key, nil); err == nil {
		t.Error("decrypting tampered ciphertext should fail")
	}
}

func TestEncryptDecryptWithAAD(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aad := []byte("record-context")
	encrypted, err := Encrypt("secret", key, aad)
	if err != nil {
		t.Fatal(err)
	}
	// correct aad succeeds
	decrypted, err := Decrypt(encrypted, key, aad)
	if err != nil {
		t.Fatalf("Decrypt with correct aad: %v", err)
	}
	if decrypted != "secret" {
		t.Errorf("decrypted = %q, want secret", decrypted)
	}
	// wrong aad fails
	if _, err := Decrypt(encrypted, key, []byte("wrong-context")); err == nil {
		t.Error("Decrypt with wrong aad should fail")
	}
}
