package userdb

import (
	"crypto/rand"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/bcrypt"
)

func TestTOTP(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "totp-user")

	t.Run("get without configuration returns disabled", func(t *testing.T) {
		got, err := mng.GetTOTP(userID)
		if err != nil {
			t.Fatal(err)
		}
		want := userauth.TOTPData{Enabled: false}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("TOTP mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("set creates and get round-trips", func(t *testing.T) {
		want := userauth.TOTPData{Enabled: true, Secret: demoTOTPSecret}
		if err := mng.SetTOTP(userID, want); err != nil {
			t.Fatal(err)
		}
		got, err := mng.GetTOTP(userID)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("TOTP mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("set updates the existing row", func(t *testing.T) {
		want := userauth.TOTPData{Enabled: false, Secret: "NEWSECRET234567A"}
		if err := mng.SetTOTP(userID, want); err != nil {
			t.Fatal(err)
		}
		got, err := mng.GetTOTP(userID)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("TOTP mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestTOTPEncrypted(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	mng := setupOpts(t, Opts{BcryptDifficulty: bcrypt.MinCost, TOTPEncryptionKey: key})
	defer clean()

	userID := mustCreateUser(t, mng, "totp-enc-user")

	want := userauth.TOTPData{Enabled: true, Secret: demoTOTPSecret}
	if err := mng.SetTOTP(userID, want); err != nil {
		t.Fatal(err)
	}

	// the secret is stored encrypted, not in plain text
	var m totpModel
	if err := mng.db.First(&m, "user_id = ?", userID).Error; err != nil {
		t.Fatal(err)
	}
	if m.Secret == want.Secret {
		t.Error("secret should be encrypted at rest")
	}

	// GetTOTP decrypts transparently
	got, err := mng.GetTOTP(userID)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TOTP mismatch (-want +got):\n%s", diff)
	}
}
