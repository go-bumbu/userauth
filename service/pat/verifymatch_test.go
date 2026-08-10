package pat_test

import (
	"crypto/md5" // #nosec G501 -- test simulates Subsonic's MD5-based salted-token auth
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/pat"
)

// mintRecoverable returns a service with a cipher plus a freshly minted
// recoverable token's record and secret.
func mintRecoverable(t *testing.T) (*pat.Service, pat.TokenRecord, string) {
	t.Helper()
	cipher, err := pat.NewAESGCMCipher(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCMCipher: %v", err)
	}
	svc, _ := newTestService(t, pat.Opts{Cipher: cipher})
	plaintext, rec, err := svc.Mint("u1", "sub client", []string{"client"}, nil, pat.Recoverable)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	secret := plaintext[strings.LastIndexByte(plaintext, '_')+1:]
	return svc, rec, secret
}

func TestVerifyMatchHappyPath(t *testing.T) {
	svc, rec, secret := mintRecoverable(t)
	// mirror the Subsonic salted-token check a consumer would implement
	salt := "c19b2d"
	sum := md5.Sum([]byte(secret + salt)) // #nosec G401 -- test simulates Subsonic's MD5 auth
	token := hex.EncodeToString(sum[:])
	info, ok, err := svc.VerifyMatch(rec.TokenID, func(s string) bool {
		got := md5.Sum([]byte(s + salt)) // #nosec G401 -- test simulates Subsonic's MD5 auth
		return hex.EncodeToString(got[:]) == token
	})
	if err != nil || !ok {
		t.Fatalf("VerifyMatch = %v, %v", ok, err)
	}
	if info.UserID != "u1" || info.LoginID != "alice@example.com" || info.TokenID != rec.TokenID {
		t.Errorf("TokenInfo mismatch: %+v", info)
	}
}

func TestVerifyMatchWrongSecret(t *testing.T) {
	svc, rec, _ := mintRecoverable(t)
	info, ok, err := svc.VerifyMatch(rec.TokenID, func(string) bool { return false })
	if err != nil || ok {
		t.Fatalf("want clean failure, got ok=%v err=%v", ok, err)
	}
	if info.UserID != "" {
		t.Errorf("failed VerifyMatch must return zero TokenInfo, got %+v", info)
	}
}

func TestVerifyMatchUnknownTokenID(t *testing.T) {
	svc, _, _ := mintRecoverable(t)
	if _, ok, err := svc.VerifyMatch("zzzzzzzzzz", func(string) bool { return true }); ok || err != nil {
		t.Errorf("unknown id: want (false, nil), got ok=%v err=%v", ok, err)
	}
}

func TestVerifyMatchHashOnlyToken(t *testing.T) {
	svc, rec, _ := mintRecoverable(t)
	_ = rec
	_, recPlain, err := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, _, err := svc.VerifyMatch(recPlain.TokenID, func(string) bool { return true }); !errors.Is(err, pat.ErrNotRecoverable) {
		t.Errorf("want ErrNotRecoverable, got %v", err)
	}
}

func TestVerifyMatchNoCipher(t *testing.T) {
	// service without cipher, record with SecretEnc inserted directly
	svc, store := newTestService(t, pat.Opts{})
	rec := pat.TokenRecord{
		TokenID: "abcdef0123", UserID: "u1", Name: "x",
		SecretHash: "deadbeef", SecretEnc: "Y3Q=", KeyID: "k1",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Insert(rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, _, err := svc.VerifyMatch("abcdef0123", func(string) bool { return true }); !errors.Is(err, pat.ErrNoCipher) {
		t.Errorf("want ErrNoCipher, got %v", err)
	}
}

func TestVerifyMatchExpiredAndDisabledOwner(t *testing.T) {
	cipher, _ := pat.NewAESGCMCipher(testKey(), "k1")

	t.Run("expired", func(t *testing.T) {
		svc, store := newTestService(t, pat.Opts{Cipher: cipher})
		plaintext, rec, err := svc.Mint("u1", "x", nil, nil, pat.Recoverable)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		secret := plaintext[strings.LastIndexByte(plaintext, '_')+1:]
		past := time.Now().Add(-time.Minute)
		expired := rec
		expired.ExpiresAt = &past
		if err := store.Delete("u1", rec.TokenID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := store.Insert(expired); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if _, ok, err := svc.VerifyMatch(rec.TokenID, func(s string) bool { return s == secret }); ok || err != nil {
			t.Errorf("expired: want (false, nil), got ok=%v err=%v", ok, err)
		}
	})

	t.Run("disabled owner", func(t *testing.T) {
		svc, _ := newTestService(t, pat.Opts{Cipher: cipher})
		plaintext, rec, err := svc.Mint("u2", "x", nil, nil, pat.Recoverable) // u2 is disabled in fakeUsers
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		secret := plaintext[strings.LastIndexByte(plaintext, '_')+1:]
		if _, ok, err := svc.VerifyMatch(rec.TokenID, func(s string) bool { return s == secret }); ok || err != nil {
			t.Errorf("disabled owner: want (false, nil), got ok=%v err=%v", ok, err)
		}
	})
}

func TestVerifyMatchTouchesLastUsed(t *testing.T) {
	cipher, _ := pat.NewAESGCMCipher(testKey(), "k1")
	svc, store := newTestService(t, pat.Opts{Cipher: cipher})
	plaintext, rec, err := svc.Mint("u1", "x", nil, nil, pat.Recoverable)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	secret := plaintext[strings.LastIndexByte(plaintext, '_')+1:]
	if _, ok, _ := svc.VerifyMatch(rec.TokenID, func(s string) bool { return s == secret }); !ok {
		t.Fatal("VerifyMatch failed")
	}
	got, _ := store.GetByTokenID(rec.TokenID)
	if got.LastUsedAt == nil {
		t.Error("VerifyMatch should set LastUsedAt")
	}
}
