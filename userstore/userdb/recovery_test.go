package userdb

import (
	"fmt"
	"testing"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// hashCodes bcrypt-hashes the given plain recovery codes.
func hashCodes(t *testing.T, codes ...string) []string {
	t.Helper()
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := hashutil.HashRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

func TestSetRecoveryCodes(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "recovery-set-user")

	t.Run("rejects more than MaxRecoveryCodes", func(t *testing.T) {
		codes := make([]string, MaxRecoveryCodes+1)
		for i := range codes {
			codes[i] = fmt.Sprintf("hash-%d", i)
		}
		if err := mng.SetRecoveryCodes(userID, codes); err == nil {
			t.Error("expected error for too many recovery codes")
		}
	})

	t.Run("stores codes and skips empty hashes", func(t *testing.T) {
		hashed := hashCodes(t, "code-1", "code-2")
		hashed = append(hashed, "") // empty hashes are skipped
		if err := mng.SetRecoveryCodes(userID, hashed); err != nil {
			t.Fatal(err)
		}
		count, err := mng.GetRecoveryCodesCount(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Errorf("want 2 stored codes, got %d", count)
		}
	})

	t.Run("replaces all previous codes", func(t *testing.T) {
		if err := mng.SetRecoveryCodes(userID, hashCodes(t, "new-code")); err != nil {
			t.Fatal(err)
		}
		count, err := mng.GetRecoveryCodesCount(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("want 1 stored code after replace, got %d", count)
		}
		if ok, _ := mng.VerifyRecoveryCode(userID, "code-1"); ok {
			t.Error("old code should have been replaced")
		}
	})

	t.Run("empty slice removes all codes", func(t *testing.T) {
		if err := mng.SetRecoveryCodes(userID, nil); err != nil {
			t.Fatal(err)
		}
		count, err := mng.GetRecoveryCodesCount(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("want 0 stored codes, got %d", count)
		}
	})
}

func TestVerifyRecoveryCode(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "recovery-verify-user")

	if err := mng.SetRecoveryCodes(userID, hashCodes(t, "alpha", "beta")); err != nil {
		t.Fatal(err)
	}

	t.Run("wrong code fails", func(t *testing.T) {
		ok, err := mng.VerifyRecoveryCode(userID, "wrong")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for wrong code")
		}
	})

	t.Run("valid code succeeds and is consumed", func(t *testing.T) {
		ok, err := mng.VerifyRecoveryCode(userID, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("expected verification success")
		}
		// consumed: same code fails a second time
		ok, err = mng.VerifyRecoveryCode(userID, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected code to be consumed after first use")
		}
		// the other code is still usable
		count, err := mng.GetRecoveryCodesCount(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("want 1 remaining code, got %d", count)
		}
	})

	t.Run("user with no codes fails", func(t *testing.T) {
		otherID := mustCreateUser(t, mng, "recovery-empty-user")
		ok, err := mng.VerifyRecoveryCode(otherID, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for user with no codes")
		}
	})
}
