package userdb

import (
	"errors"
	"testing"

	"github.com/go-bumbu/userauth/service/totp"
	"github.com/google/go-cmp/cmp"
)

func TestTOTPStore(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "totp-user")
	store := mng.TOTPStore()

	t.Run("get without enrolment reports ErrNotEnrolled", func(t *testing.T) {
		if _, err := store.Get(userID); !errors.Is(err, totp.ErrNotEnrolled) {
			t.Errorf("Get: err = %v, want totp.ErrNotEnrolled", err)
		}
	})

	t.Run("set creates and get round-trips", func(t *testing.T) {
		want := totp.Record{Secret: demoTOTPSecret, KeyID: "k1", Enabled: true}
		if err := store.Set(userID, want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(userID)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("record mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("set updates the existing row", func(t *testing.T) {
		want := totp.Record{Secret: "NEWSECRET234567A", Enabled: false}
		if err := store.Set(userID, want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(userID)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("record mismatch (-want +got):\n%s", diff)
		}
		// one row per user, not one per Set
		var count int64
		if err := mng.db.Model(&totpModel{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("stored %d rows for one user, want 1", count)
		}
	})

	t.Run("delete removes the enrolment", func(t *testing.T) {
		if err := store.Delete(userID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(userID); !errors.Is(err, totp.ErrNotEnrolled) {
			t.Errorf("Get after Delete: err = %v, want totp.ErrNotEnrolled", err)
		}
	})
}

// TestTOTPStoreKeepsSecretOpaque documents the layering: the store persists
// whatever service/totp hands it and never encrypts, decrypts, or validates.
func TestTOTPStoreKeepsSecretOpaque(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "totp-opaque-user")
	const ciphertext = "not-a-base32-secret"
	if err := mng.TOTPStore().Set(userID, totp.Record{Secret: ciphertext, KeyID: "k1", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	var m totpModel
	if err := mng.db.First(&m, "user_id = ?", userID).Error; err != nil {
		t.Fatal(err)
	}
	if m.Secret != ciphertext || m.KeyID != "k1" {
		t.Errorf("stored (%q, %q), want the values as handed over", m.Secret, m.KeyID)
	}
}

// TestTOTPEnabledDoesNotNeedTheSecret pins that AvailableSecondFactors can
// answer without a decryption key: it reads the flag only.
func TestTOTPEnabledDoesNotNeedTheSecret(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "totp-flag-user")

	on, err := mng.totpEnabled(userID)
	if err != nil {
		t.Fatal(err)
	}
	if on {
		t.Error("a user with no enrolment must report disabled")
	}

	// a pending enrolment is not an enabled factor
	if err := mng.TOTPStore().Set(userID, totp.Record{Secret: "ciphertext", KeyID: "k1", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if on, err = mng.totpEnabled(userID); err != nil || on {
		t.Errorf("pending enrolment = (%v, %v), want (false, nil)", on, err)
	}

	if err := mng.TOTPStore().Set(userID, totp.Record{Secret: "ciphertext", KeyID: "k1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if on, err = mng.totpEnabled(userID); err != nil || !on {
		t.Errorf("confirmed enrolment = (%v, %v), want (true, nil)", on, err)
	}
}
