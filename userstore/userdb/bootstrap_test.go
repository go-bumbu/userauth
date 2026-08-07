package userdb

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"golang.org/x/crypto/bcrypt"
)

func TestCountIsEmpty(t *testing.T) {
	mng := setup(t)
	defer clean()

	total, err := mng.Count()
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Errorf("want count 0, got %d", total)
	}
	empty, err := mng.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("want empty store")
	}

	if err := mng.Create("u1", "pw"); err != nil {
		t.Fatal(err)
	}

	total, err = mng.Count()
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("want count 1, got %d", total)
	}
	empty, err = mng.IsEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("want non-empty store")
	}
}

func TestBootstrap(t *testing.T) {
	t.Run("seeds empty store", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		seeded, err := mng.Bootstrap(
			User{LoginID: "admin", Pw: "secret", Enabled: true},
			User{LoginID: "backup-admin", Pw: "secret2", Enabled: true},
		)
		if err != nil {
			t.Fatal(err)
		}
		if !seeded {
			t.Error("want seeded=true on empty store")
		}

		u, err := mng.GetUserByLogin("admin")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := hashutil.VerifyPassword("secret", u.HashPw)
		if err != nil || !ok {
			t.Errorf("bootstrapped user password should verify: ok=%v err=%v", ok, err)
		}
		if total, _ := mng.Count(); total != 2 {
			t.Errorf("want 2 users, got %d", total)
		}
	})

	t.Run("no-op on populated store", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if err := mng.Create("existing", "pw"); err != nil {
			t.Fatal(err)
		}
		seeded, err := mng.Bootstrap(User{LoginID: "admin", Pw: "secret", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if seeded {
			t.Error("want seeded=false on populated store")
		}
		if _, err := mng.GetUserByLogin("admin"); !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("admin should not exist, got err=%v", err)
		}
	})

	t.Run("no-op after bootstrapped admin is replaced and deleted", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if _, err := mng.Bootstrap(User{LoginID: "admin", Pw: "secret", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := mng.Create("admin2", "pw"); err != nil {
			t.Fatal(err)
		}
		admin, err := mng.GetUserByLogin("admin")
		if err != nil {
			t.Fatal(err)
		}
		if err := mng.Delete(admin.ID); err != nil {
			t.Fatal(err)
		}

		// config still there: bootstrap runs again on restart, must not resurrect admin
		seeded, err := mng.Bootstrap(User{LoginID: "admin", Pw: "secret", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if seeded {
			t.Error("want seeded=false, store is not empty")
		}
		if _, err := mng.GetUserByLogin("admin"); !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("deleted admin should not be resurrected, got err=%v", err)
		}
	})

}

func TestBootstrapPasswordHashing(t *testing.T) {
	t.Run("pre-hashed password", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mng.Bootstrap(User{LoginID: "admin", Pw: string(hash), PwIsHashed: true, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		u, err := mng.GetUserByLogin("admin")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := hashutil.VerifyPassword("secret", u.HashPw)
		if err != nil || !ok {
			t.Errorf("pre-hashed password should verify: ok=%v err=%v", ok, err)
		}
	})

	t.Run("rejects invalid pre-hashed password", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		notABcryptHash := strings.Repeat("x", 20)
		_, err := mng.Bootstrap(User{LoginID: "admin", Pw: notABcryptHash, PwIsHashed: true, Enabled: true})
		if err == nil {
			t.Fatal("want error for non-bcrypt hash")
		}
		// failed bootstrap must not leave partial state
		if empty, _ := mng.IsEmpty(); !empty {
			t.Error("store should remain empty after failed bootstrap")
		}
	})

}

func TestBootstrapInvalidInput(t *testing.T) {
	t.Run("partial failure rolls back all users", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		_, err := mng.Bootstrap(
			User{LoginID: "admin", Pw: "secret", Enabled: true},
			User{LoginID: "", Pw: "secret", Enabled: true}, // invalid
		)
		if err == nil {
			t.Fatal("want error for invalid second user")
		}
		if empty, _ := mng.IsEmpty(); !empty {
			t.Error("store should remain empty after failed bootstrap")
		}
	})

	t.Run("requires at least one user", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if _, err := mng.Bootstrap(); err == nil {
			t.Fatal("want error for empty user list")
		}
	})
}

func TestDelete(t *testing.T) {
	t.Run("removes user and associated data", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if err := mng.Create("alice", "pw"); err != nil {
			t.Fatal(err)
		}
		alice, err := mng.GetUserByLogin("alice")
		if err != nil {
			t.Fatal(err)
		}
		if err := mng.SetRecoveryCodes(alice.ID, []string{hashutil.MustHashPassword("code1")}); err != nil {
			t.Fatal(err)
		}

		if err := mng.Delete(alice.ID); err != nil {
			t.Fatal(err)
		}

		if _, err := mng.GetUserByLogin("alice"); !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("want ErrUserNotFound, got %v", err)
		}
		if n, _ := mng.GetRecoveryCodesCount(alice.ID); n != 0 {
			t.Errorf("want 0 recovery codes after delete, got %d", n)
		}
	})

	t.Run("login ID can be reused after delete", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if err := mng.Create("alice", "pw"); err != nil {
			t.Fatal(err)
		}
		alice, err := mng.GetUserByLogin("alice")
		if err != nil {
			t.Fatal(err)
		}
		if err := mng.Delete(alice.ID); err != nil {
			t.Fatal(err)
		}
		if err := mng.Create("alice", "pw2"); err != nil {
			t.Errorf("recreating deleted user should succeed, got %v", err)
		}
	})

	t.Run("unknown user returns ErrUserNotFound", func(t *testing.T) {
		mng := setup(t)
		defer clean()

		if err := mng.Delete("ghost"); !errors.Is(err, userauth.ErrUserNotFound) {
			t.Errorf("want ErrUserNotFound, got %v", err)
		}
	})
}
