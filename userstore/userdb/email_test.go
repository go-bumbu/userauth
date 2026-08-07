package userdb

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

func TestEmailCodeVerify(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "email-user")
	future := time.Now().UTC().Add(time.Hour)

	t.Run("verify with no stored code fails", func(t *testing.T) {
		ok, err := mng.VerifyEmailCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure with no stored code")
		}
	})

	t.Run("store and verify consumes the code", func(t *testing.T) {
		if err := mng.StoreEmailCode(userID, hashutil.HashCodeSHA256("123456"), future); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifyEmailCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("expected verification success")
		}
		// second attempt fails: code consumed
		ok, err = mng.VerifyEmailCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected code to be consumed after first verification")
		}
	})

	t.Run("wrong code fails", func(t *testing.T) {
		if err := mng.StoreEmailCode(userID, hashutil.HashCodeSHA256("111111"), future); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifyEmailCode(userID, "222222")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for wrong code")
		}
	})

	t.Run("storing a new code replaces the old one", func(t *testing.T) {
		if err := mng.StoreEmailCode(userID, hashutil.HashCodeSHA256("first"), future); err != nil {
			t.Fatal(err)
		}
		if err := mng.StoreEmailCode(userID, hashutil.HashCodeSHA256("second"), future); err != nil {
			t.Fatal(err)
		}
		if ok, _ := mng.VerifyEmailCode(userID, "first"); ok {
			t.Error("old code should have been replaced")
		}
		if ok, _ := mng.VerifyEmailCode(userID, "second"); !ok {
			t.Error("new code should verify")
		}
	})

	t.Run("expired code fails and is removed", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Hour)
		if err := mng.StoreEmailCode(userID, hashutil.HashCodeSHA256("expired"), past); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifyEmailCode(userID, "expired")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for expired code")
		}
	})
}

func TestSetEmailCodeEnabled(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "email-flags-user")

	t.Run("defaults to disabled", func(t *testing.T) {
		enabled, err := mng.emailCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Error("expected email 2FA disabled by default")
		}
	})

	t.Run("enable creates the flags row", func(t *testing.T) {
		if err := mng.SetEmailCodeEnabled(userID, true); err != nil {
			t.Fatal(err)
		}
		enabled, err := mng.emailCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			t.Error("expected email 2FA enabled")
		}
	})

	t.Run("disable updates the existing row", func(t *testing.T) {
		if err := mng.SetEmailCodeEnabled(userID, false); err != nil {
			t.Fatal(err)
		}
		enabled, err := mng.emailCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Error("expected email 2FA disabled")
		}
	})
}

func TestPendingEmailChange(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "pending-email-user")
	future := time.Now().UTC().Add(time.Hour)

	t.Run("get with no pending change fails", func(t *testing.T) {
		_, err := mng.GetPendingEmailChange(userID)
		if err == nil {
			t.Error("expected error when no pending change exists")
		}
	})

	t.Run("store and get", func(t *testing.T) {
		err := mng.StorePendingEmailChange(userID, "new@mail.com", hashutil.HashCodeSHA256("123456"), future)
		if err != nil {
			t.Fatal(err)
		}
		got, err := mng.GetPendingEmailChange(userID)
		if err != nil {
			t.Fatal(err)
		}
		if got != "new@mail.com" {
			t.Errorf("want new@mail.com, got %q", got)
		}
	})

	t.Run("verify with wrong code fails", func(t *testing.T) {
		_, err := mng.VerifyPendingEmailChange(userID, "wrong")
		if err == nil {
			t.Error("expected error for wrong code")
		}
	})

	t.Run("verify consumes the pending change", func(t *testing.T) {
		got, err := mng.VerifyPendingEmailChange(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if got != "new@mail.com" {
			t.Errorf("want new@mail.com, got %q", got)
		}
		// consumed: a second verify fails
		if _, err := mng.VerifyPendingEmailChange(userID, "123456"); err == nil {
			t.Error("expected error after pending change was consumed")
		}
	})

	t.Run("storing a new pending change replaces the old one", func(t *testing.T) {
		if err := mng.StorePendingEmailChange(userID, "a@mail.com", hashutil.HashCodeSHA256("aaa"), future); err != nil {
			t.Fatal(err)
		}
		if err := mng.StorePendingEmailChange(userID, "b@mail.com", hashutil.HashCodeSHA256("bbb"), future); err != nil {
			t.Fatal(err)
		}
		if _, err := mng.VerifyPendingEmailChange(userID, "aaa"); err == nil {
			t.Error("old pending change should have been replaced")
		}
		got, err := mng.VerifyPendingEmailChange(userID, "bbb")
		if err != nil {
			t.Fatal(err)
		}
		if got != "b@mail.com" {
			t.Errorf("want b@mail.com, got %q", got)
		}
	})
}

func TestPendingEmailChangeExpired(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "pending-email-expired-user")
	past := time.Now().UTC().Add(-time.Hour)

	t.Run("get expired change fails", func(t *testing.T) {
		err := mng.StorePendingEmailChange(userID, "x@mail.com", hashutil.HashCodeSHA256("xxx"), past)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mng.GetPendingEmailChange(userID); err == nil {
			t.Error("expected error for expired pending change")
		}
	})

	t.Run("verify expired change fails", func(t *testing.T) {
		err := mng.StorePendingEmailChange(userID, "y@mail.com", hashutil.HashCodeSHA256("yyy"), past)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mng.VerifyPendingEmailChange(userID, "yyy"); err == nil {
			t.Error("expected error for expired pending change")
		}
	})
}
