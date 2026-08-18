package db

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
	"github.com/go-bumbu/userauth/service/cipher"
	"github.com/go-bumbu/userauth/service/totp"
	otptotp "github.com/pquerna/otp/totp"
)

// TestTOTPSecretsEncryptedBeforeTheServiceOwnedTheCipher is the migration
// guard. Before service/totp existed, userdb encrypted TOTP secrets itself with
// hashutil.Encrypt(secret, key, nil) and had no key-id column. Moving the key
// into totp.Opts.Cipher is meant to be a configuration change only — this test
// writes a row exactly as the old code path did and asserts the service still
// verifies codes against it.
func TestTOTPSecretsEncryptedBeforeTheServiceOwnedTheCipher(t *testing.T) {
	store := newStore(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	const secret = "JBSWY3DPEHPK3PXP" //nolint:gosec // well-known RFC example secret
	// exactly what the old userdb.SetTOTP wrote: ciphertext, no AAD, no key id
	legacy, err := hashutil.Encrypt(secret, key, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := store.Set("user1", totp.Record{Secret: legacy, Enabled: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	secretCipher, err := cipher.NewAESGCM(key, "k1")
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	svc, err := totp.NewService(store, totp.Opts{Issuer: "test", Cipher: secretCipher})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	code, err := otptotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	ok, err := svc.Verify("user1", code)
	if err != nil {
		t.Fatalf("Verify on a pre-service row: %v", err)
	}
	if !ok {
		t.Error("a TOTP secret encrypted before the service owned the cipher must still verify")
	}
}
