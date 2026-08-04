package userdb

import (
	"errors"
	"testing"

	"github.com/go-bumbu/userauth"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateValidation(t *testing.T) {
	mng := setupOpts(t, Opts{
		BcryptDifficulty: bcrypt.MinCost,
		UsernameFormat:   userauth.UsernameFormatEmail,
		DefaultEnabled:   true,
	})
	defer clean()

	t.Run("rejects login ID that violates the username format", func(t *testing.T) {
		if err := mng.Create("not-an-email", "pw"); err == nil {
			t.Error("expected error for non-email login ID with email format policy")
		}
	})

	t.Run("accepts valid login ID and applies defaultEnabled", func(t *testing.T) {
		if err := mng.Create("valid@mail.com", "pw"); err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUserByLogin("valid@mail.com")
		if err != nil {
			t.Fatal(err)
		}
		if !u.Enabled {
			t.Error("expected user enabled via DefaultEnabled")
		}
	})
}

func TestCreateUserValidation(t *testing.T) {
	mng := setup(t)
	defer clean()

	tcs := []struct {
		name string
		usr  User
	}{
		{"empty login ID", User{Pw: "pw"}},
		{"empty password", User{LoginID: "someone"}},
		{"flagged hashed but not a hash", User{LoginID: "someone", Pw: "plaintext", PwIsHashed: true}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := mng.CreateUser(tc.usr); err == nil {
				t.Error("expected error")
			}
		})
	}

	t.Run("duplicate login ID fails", func(t *testing.T) {
		if err := mng.Create("dup-user", "pw"); err != nil {
			t.Fatal(err)
		}
		if err := mng.Create("dup-user", "pw"); err == nil {
			t.Error("expected error for duplicate login ID")
		}
	})

	t.Run("initial groups are stored", func(t *testing.T) {
		err := mng.CreateUser(User{LoginID: "grouped", Pw: "pw", Groups: []string{"admin", "dev"}})
		if err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUserByLogin("grouped")
		if err != nil {
			t.Fatal(err)
		}
		groups, err := mng.GetGroups(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 || groups[0] != "admin" || groups[1] != "dev" {
			t.Errorf("want [admin dev], got %v", groups)
		}
	})
}

func TestSetLoginID(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "old-login")

	t.Run("renames and keeps the canonical ID", func(t *testing.T) {
		if err := mng.SetLoginID(userID, "new-login"); err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUserByLogin("new-login")
		if err != nil {
			t.Fatal(err)
		}
		if u.ID != userID {
			t.Errorf("canonical ID changed: want %q, got %q", userID, u.ID)
		}
		if _, err := mng.GetUserByLogin("old-login"); !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("old login should be gone, got err=%v", err)
		}
	})

	t.Run("unknown user returns ErrUserNotFound", func(t *testing.T) {
		err := mng.SetLoginID("no-such-uuid", "whatever")
		if !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("want ErrUserNotFound, got %v", err)
		}
	})

	t.Run("invalid format is rejected", func(t *testing.T) {
		mngEmail := setupOpts(t, Opts{BcryptDifficulty: bcrypt.MinCost, UsernameFormat: userauth.UsernameFormatEmail})
		if err := mngEmail.SetLoginID(userID, "not-an-email"); err == nil {
			t.Error("expected error for login ID violating the format policy")
		}
	})

	t.Run("taken login ID is rejected", func(t *testing.T) {
		otherID := mustCreateUser(t, mng, "other-login")
		if err := mng.SetLoginID(otherID, "new-login"); err == nil {
			t.Error("expected error when renaming to a taken login ID")
		}
	})
}

func TestSetPrimaryEmail(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "email-set-user")

	t.Run("set email resets verified flag", func(t *testing.T) {
		if err := mng.SetPrimaryEmailVerified(userID, true); err != nil {
			t.Fatal(err)
		}
		if err := mng.SetPrimaryEmail(userID, "primary@mail.com"); err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUser(userID)
		if err != nil {
			t.Fatal(err)
		}
		if u.PrimaryEmail != "primary@mail.com" {
			t.Errorf("want primary@mail.com, got %q", u.PrimaryEmail)
		}
		if u.PrimaryEmailVerified {
			t.Error("verified flag should be reset when the email changes")
		}
	})

	t.Run("mark verified", func(t *testing.T) {
		if err := mng.SetPrimaryEmailVerified(userID, true); err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUser(userID)
		if err != nil {
			t.Fatal(err)
		}
		if !u.PrimaryEmailVerified {
			t.Error("expected primary email verified")
		}
	})
}

func TestSetEnabled(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "enable-user")

	if err := mng.SetEnabled(userID, false); err != nil {
		t.Fatal(err)
	}
	u, err := mng.GetUser(userID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Enabled {
		t.Error("expected user disabled")
	}

	if err := mng.SetEnabled(userID, true); err != nil {
		t.Fatal(err)
	}
	u, err = mng.GetUser(userID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Enabled {
		t.Error("expected user enabled")
	}
}

func TestDeleteNotFound(t *testing.T) {
	mng := setup(t)
	defer clean()

	err := mng.Delete("no-such-uuid")
	if !errors.Is(err, userauth.ErrUserNotFound) {
		t.Errorf("want ErrUserNotFound, got %v", err)
	}
}

func TestListLimitCap(t *testing.T) {
	mng := setup(t)
	defer clean()

	if err := mng.Create("cap-user", "pw"); err != nil {
		t.Fatal(err)
	}

	// a limit above maxListLimit is capped, not an error
	res, err := mng.List(ListOpts{Limit: maxListLimit + 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Users) != 1 {
		t.Errorf("want 1 user, got total=%d len=%d", res.Total, len(res.Users))
	}
}
