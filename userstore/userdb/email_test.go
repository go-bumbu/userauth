package userdb

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

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
		_, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("wrong"))
		if err == nil {
			t.Error("expected error for wrong code")
		}
	})

	t.Run("verify consumes the pending change", func(t *testing.T) {
		got, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("123456"))
		if err != nil {
			t.Fatal(err)
		}
		if got != "new@mail.com" {
			t.Errorf("want new@mail.com, got %q", got)
		}
		// consumed: a second verify fails
		if _, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("123456")); err == nil {
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
		if _, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("aaa")); err == nil {
			t.Error("old pending change should have been replaced")
		}
		got, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("bbb"))
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
		if _, err := mng.ConsumePendingEmailChange(userID, hashutil.HashCodeSHA256("yyy")); err == nil {
			t.Error("expected error for expired pending change")
		}
	})
}
