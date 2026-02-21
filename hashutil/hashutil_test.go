package hashutil

import (
	"errors"
	"testing"
)

func TestHashPassword_VerifyPassword(t *testing.T) {
	password := "secret"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" || hash == password {
		t.Errorf("hash should be different from plain password")
	}
	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("VerifyPassword should succeed for correct password")
	}
	ok, _ = VerifyPassword("wrong", hash)
	if ok {
		t.Error("VerifyPassword should fail for wrong password")
	}
}

func TestVerifyPassword_UnknownAlgorithm(t *testing.T) {
	_, err := VerifyPassword("demo", "plaintext")
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	if !isErrUnknownAlgorithm(err) {
		t.Errorf("expected ErrUnknownAlgorithm, got %v", err)
	}
}

func isErrUnknownAlgorithm(err error) bool {
	return errors.Is(err, ErrUnknownAlgorithm)
}

func TestHashRecoveryCode(t *testing.T) {
	code := "abcd-1234"
	h1 := HashRecoveryCode(code)
	h2 := HashRecoveryCode(code)
	if h1 != h2 {
		t.Error("same code should produce same hash")
	}
	if h1 == "" || h1 == code {
		t.Error("hash should be non-empty and not equal to plain code")
	}
	// Trimmed input
	h3 := HashRecoveryCode("  " + code + "  ")
	if h1 != h3 {
		t.Error("trimmed code should produce same hash")
	}
}

func TestAlg(t *testing.T) {
	if Alg("$2b$10$xyz") != Bcrypt {
		t.Error("bcrypt hash should be detected")
	}
	if Alg("plain") != Unknown {
		t.Error("plain text should be Unknown")
	}
}
