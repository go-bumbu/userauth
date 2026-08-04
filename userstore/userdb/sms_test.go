package userdb

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

func TestSMSCodeVerify(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "sms-user")
	future := time.Now().UTC().Add(time.Hour)

	t.Run("verify with no stored code fails", func(t *testing.T) {
		ok, err := mng.VerifySMSCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure with no stored code")
		}
	})

	t.Run("store and verify consumes the code", func(t *testing.T) {
		if err := mng.StoreSMSCode(userID, hashutil.HashCodeSHA256("123456"), future); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifySMSCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("expected verification success")
		}
		ok, err = mng.VerifySMSCode(userID, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected code to be consumed after first verification")
		}
	})

	t.Run("wrong code fails", func(t *testing.T) {
		if err := mng.StoreSMSCode(userID, hashutil.HashCodeSHA256("111111"), future); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifySMSCode(userID, "222222")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for wrong code")
		}
	})

	t.Run("storing a new code replaces the old one", func(t *testing.T) {
		if err := mng.StoreSMSCode(userID, hashutil.HashCodeSHA256("first"), future); err != nil {
			t.Fatal(err)
		}
		if err := mng.StoreSMSCode(userID, hashutil.HashCodeSHA256("second"), future); err != nil {
			t.Fatal(err)
		}
		if ok, _ := mng.VerifySMSCode(userID, "first"); ok {
			t.Error("old code should have been replaced")
		}
		if ok, _ := mng.VerifySMSCode(userID, "second"); !ok {
			t.Error("new code should verify")
		}
	})

	t.Run("expired code fails and is removed", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Hour)
		if err := mng.StoreSMSCode(userID, hashutil.HashCodeSHA256("expired"), past); err != nil {
			t.Fatal(err)
		}
		ok, err := mng.VerifySMSCode(userID, "expired")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("expected verification failure for expired code")
		}
	})
}

func TestSetSMSCodeEnabled(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "sms-flags-user")

	t.Run("defaults to disabled", func(t *testing.T) {
		enabled, err := mng.smsCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Error("expected SMS 2FA disabled by default")
		}
	})

	t.Run("enable creates the flags row", func(t *testing.T) {
		if err := mng.SetSMSCodeEnabled(userID, true); err != nil {
			t.Fatal(err)
		}
		enabled, err := mng.smsCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			t.Error("expected SMS 2FA enabled")
		}
	})

	t.Run("disable updates the existing row", func(t *testing.T) {
		if err := mng.SetSMSCodeEnabled(userID, false); err != nil {
			t.Fatal(err)
		}
		enabled, err := mng.smsCodeEnabled(userID)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Error("expected SMS 2FA disabled")
		}
	})
}
