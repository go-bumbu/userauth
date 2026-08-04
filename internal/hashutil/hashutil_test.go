package hashutil

import (
	"errors"
	"strings"
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
	code := "abcd1234"
	h1, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == "" || h1 == code {
		t.Error("hash should be non-empty and not equal to plain code")
	}
	// bcrypt produces different hashes each time (random salt)
	h2, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("bcrypt hashes should differ due to random salt")
	}
	// Both should verify against the original code
	if !VerifyRecoveryCodeHash(code, h1) {
		t.Error("VerifyRecoveryCodeHash should succeed for correct code against h1")
	}
	if !VerifyRecoveryCodeHash(code, h2) {
		t.Error("VerifyRecoveryCodeHash should succeed for correct code against h2")
	}
	// Trimmed input should also match
	if !VerifyRecoveryCodeHash("  "+code+"  ", h1) {
		t.Error("trimmed code should verify against hash")
	}
	// Wrong code should not match
	if VerifyRecoveryCodeHash("wrong", h1) {
		t.Error("VerifyRecoveryCodeHash should fail for wrong code")
	}
}

func TestHashCodeSHA256(t *testing.T) {
	code := "abcd-1234"
	h1 := HashCodeSHA256(code)
	h2 := HashCodeSHA256(code)
	if h1 != h2 {
		t.Error("same code should produce same hash")
	}
	if h1 == "" || h1 == code {
		t.Error("hash should be non-empty and not equal to plain code")
	}
	// Trimmed input
	h3 := HashCodeSHA256("  " + code + "  ")
	if h1 != h3 {
		t.Error("trimmed code should produce same hash")
	}
}

func TestAlg(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want HashAlgo
	}{
		{name: "legacy $2$ prefix", hash: "$2$10$xyz", want: Bcrypt},
		{name: "$2a$ prefix", hash: "$2a$10$xyz", want: Bcrypt},
		{name: "$2b$ prefix", hash: "$2b$10$xyz", want: Bcrypt},
		{name: "$2x$ prefix", hash: "$2x$10$xyz", want: Bcrypt},
		{name: "$2y$ prefix", hash: "$2y$10$xyz", want: Bcrypt},
		{name: "plain text", hash: "plain", want: Unknown},
		{name: "empty string", hash: "", want: Unknown},
		{name: "shorter than prefix", hash: "$2a", want: Unknown},
		{name: "unknown dollar prefix", hash: "$9z$10$xyz", want: Unknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Alg(tc.hash); got != tc.want {
				t.Errorf("Alg(%q) = %v, want %v", tc.hash, got, tc.want)
			}
		})
	}
}

func TestMustHashPassword(t *testing.T) {
	hash := MustHashPassword("secret")
	ok, err := VerifyPassword("secret", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("MustHashPassword hash should verify against original password")
	}
}

func TestMustHashPassword_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustHashPassword should panic when hashing fails")
		}
	}()
	// bcrypt rejects passwords longer than 72 bytes, forcing the panic path.
	MustHashPassword(strings.Repeat("a", 73))
}

func TestVerifyPassword_MalformedBcryptHash(t *testing.T) {
	// Bcrypt prefix so Alg detects it, but too short to be a valid hash:
	// bcrypt returns a non-mismatch error which VerifyPassword must propagate.
	ok, err := VerifyPassword("secret", "$2a$10$short")
	if ok {
		t.Error("malformed hash should not verify")
	}
	if err == nil {
		t.Error("expected error for malformed bcrypt hash")
	}
	if errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("expected bcrypt error, got ErrUnknownAlgorithm: %v", err)
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Run("valid count", func(t *testing.T) {
		codes, err := GenerateRecoveryCodes(5)
		if err != nil {
			t.Fatal(err)
		}
		if len(codes) != 5 {
			t.Fatalf("want 5 codes, got %d", len(codes))
		}
		seen := map[string]bool{}
		for _, code := range codes {
			if len(code) != 8 {
				t.Errorf("code %q should be 8 characters", code)
			}
			for _, r := range code {
				if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", r) {
					t.Errorf("code %q contains character %q outside charset", code, r)
				}
			}
			seen[code] = true
		}
		if len(seen) != len(codes) {
			t.Errorf("codes should be unique, got %d distinct of %d", len(seen), len(codes))
		}
	})

	t.Run("invalid count", func(t *testing.T) {
		for _, count := range []int{0, -1, 101} {
			if _, err := GenerateRecoveryCodes(count); err == nil {
				t.Errorf("GenerateRecoveryCodes(%d) should fail", count)
			}
		}
	})
}

func TestGenerateNumericCode(t *testing.T) {
	for _, length := range []int{0, 1, 6, 10} {
		code, err := GenerateNumericCode(length)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != length {
			t.Errorf("want code of length %d, got %q (len %d)", length, code, len(code))
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Errorf("code %q contains non-digit %q", code, r)
			}
		}
	}
}
