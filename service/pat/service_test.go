package pat_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
)

// fakeUsers is a minimal userauth.UserGetter for service tests.
type fakeUsers struct {
	users map[string]userauth.User
}

func (f fakeUsers) GetUser(id string) (userauth.User, error) {
	u, ok := f.users[id]
	if !ok {
		return userauth.User{}, userauth.ErrUserNotFound
	}
	return u, nil
}

func (f fakeUsers) GetUserByLogin(loginID string) (userauth.User, error) {
	for _, u := range f.users {
		if u.LoginID == loginID {
			return u, nil
		}
	}
	return userauth.User{}, userauth.ErrUserNotFound
}

func newTestService(t *testing.T, opts pat.Opts) (*pat.Service, *memory.Store) {
	t.Helper()
	store := memory.New()
	users := fakeUsers{users: map[string]userauth.User{
		"u1": {ID: "u1", LoginID: "alice@example.com", Enabled: true},
		"u2": {ID: "u2", LoginID: "bob@example.com", Enabled: false},
	}}
	svc, err := pat.NewService(store, users, opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func TestMintFormatAndStorage(t *testing.T) {
	svc, store := newTestService(t, pat.Opts{})
	exp := time.Now().Add(24 * time.Hour)
	plaintext, rec, err := svc.Mint("u1", "ci token", []string{"read"}, &exp, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(plaintext, "pat_") {
		t.Errorf("plaintext %q should start with default prefix", plaintext)
	}
	parts := strings.Split(plaintext, "_")
	if len(parts) != 3 || len(parts[1]) != 10 || len(parts[2]) != 43 {
		t.Errorf("token shape wrong: %q", plaintext)
	}
	if parts[1] != strings.ToLower(parts[1]) {
		t.Errorf("tokenID %q must be lowercase (base36): it is used as a virtual username and must survive case-mangling clients", parts[1])
	}
	if rec.TokenID != parts[1] {
		t.Errorf("record TokenID %q != token part %q", rec.TokenID, parts[1])
	}
	// once-only plaintext: the stored record holds only the SHA-256 hash
	stored, err := store.GetByTokenID(rec.TokenID)
	if err != nil {
		t.Fatalf("GetByTokenID: %v", err)
	}
	if stored.SecretHash == "" || strings.Contains(stored.SecretHash, parts[2]) {
		t.Errorf("store must hold a hash, never the secret: %q", stored.SecretHash)
	}
	if stored.ExpiresAt == nil {
		t.Error("expiry not persisted")
	}
}

func TestMintCustomPrefix(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{Prefix: "myapp_pat"})
	plaintext, _, err := svc.Mint("u1", "x", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(plaintext, "myapp_pat_") {
		t.Errorf("plaintext %q should carry custom prefix", plaintext)
	}
}

func TestMintValidation(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{})
	past := time.Now().Add(-time.Hour)
	tests := []struct {
		name      string
		tokenName string
		expiresAt *time.Time
		wantErr   error
	}{
		{"empty name", "", nil, pat.ErrInvalidName},
		{"blank name", "   ", nil, pat.ErrInvalidName},
		{"over-long name", strings.Repeat("x", 101), nil, pat.ErrInvalidName},
		{"past expiry", "ok", &past, pat.ErrInvalidExpiry},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Mint("u1", tc.tokenName, nil, tc.expiresAt, pat.HashOnly)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestMintMaxPerUser(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{MaxPerUser: 2})
	for i := 0; i < 2; i++ {
		if _, _, err := svc.Mint("u1", "tok", nil, nil, pat.HashOnly); err != nil {
			t.Fatalf("Mint %d: %v", i, err)
		}
	}
	if _, _, err := svc.Mint("u1", "tok", nil, nil, pat.HashOnly); !errors.Is(err, pat.ErrTooManyTokens) {
		t.Errorf("want ErrTooManyTokens, got %v", err)
	}
	// other users unaffected
	if _, _, err := svc.Mint("u2", "tok", nil, nil, pat.HashOnly); err != nil {
		t.Errorf("other user's Mint: %v", err)
	}
}

func TestListAndRevoke(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{})
	_, rec, err := svc.Mint("u1", "mine", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	got, err := svc.List("u1")
	if err != nil || len(got) != 1 || got[0].TokenID != rec.TokenID {
		t.Fatalf("List = %+v, %v", got, err)
	}
	// foreign revoke fails, owner revoke succeeds
	if err := svc.Revoke("u2", rec.TokenID); !errors.Is(err, pat.ErrTokenNotFound) {
		t.Errorf("foreign Revoke: want ErrTokenNotFound, got %v", err)
	}
	if err := svc.Revoke("u1", rec.TokenID); err != nil {
		t.Errorf("owner Revoke: %v", err)
	}
	got, _ = svc.List("u1")
	if len(got) != 0 {
		t.Errorf("token still listed after revoke: %+v", got)
	}
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := pat.NewService(nil, fakeUsers{}, pat.Opts{}); err == nil {
		t.Error("nil store should error")
	}
	if _, err := pat.NewService(memory.New(), nil, pat.Opts{}); err == nil {
		t.Error("nil users should error")
	}
}

func TestMintRecoverableStoresEncryptedSecret(t *testing.T) {
	cipher, err := pat.NewAESGCMCipher(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCMCipher: %v", err)
	}
	svc, store := newTestService(t, pat.Opts{Cipher: cipher})
	plaintext, rec, err := svc.Mint("u1", "sub client", nil, nil, pat.Recoverable)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	stored, err := store.GetByTokenID(rec.TokenID)
	if err != nil {
		t.Fatalf("GetByTokenID: %v", err)
	}
	if !stored.Recoverable() || stored.KeyID != "k1" {
		t.Fatalf("record not recoverable: %+v", stored)
	}
	if stored.SecretHash == "" {
		t.Error("SecretHash must stay populated on recoverable tokens (apiKey path)")
	}
	secret := plaintext[strings.LastIndexByte(plaintext, '_')+1:]
	got, err := cipher.Decrypt(stored.SecretEnc, stored.KeyID)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Errorf("decrypted secret %q != minted secret %q", got, secret)
	}
}

func TestMintRecoverableWithoutCipherFails(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{})
	if _, _, err := svc.Mint("u1", "x", nil, nil, pat.Recoverable); !errors.Is(err, pat.ErrNoCipher) {
		t.Errorf("want ErrNoCipher, got %v", err)
	}
}
