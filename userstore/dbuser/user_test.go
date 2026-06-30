package dbuser

import (
	"testing"

	"github.com/go-bumbu/userauth/hashutil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateUser(t *testing.T) {

	mng := setup(t)
	defer clean()

	err := mng.CreateUser(User{
		Name:    "test",
		LoginID: "test@mail.com",
		Pw:      "1234",
	})

	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	// Reads
	var got userModel
	mng.db.First(&got, 1)

	want := userModel{
		Name:    "test",
		LoginID: "test@mail.com",
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(userModel{}, "Model", "Pw")); diff != "" {
		t.Errorf("Content mismatch (-want +got):\n%s", diff)
	}
}

func TestLogin(t *testing.T) {
	mng := setup(t)
	defer clean()

	_ = mng.CreateUser(User{
		Name:    "test",
		LoginID: "test@mail.com",
		Pw:      "1234",
	})

	t.Run("assert correct login", func(t *testing.T) {
		u, err := mng.GetUser("test@mail.com")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := hashutil.VerifyPassword("1234", u.HashPw)
		if err != nil || !ok {
			t.Errorf("expecting login success: ok=%v err=%v", ok, err)
		}
	})

	t.Run("assert wrong password login", func(t *testing.T) {
		u, err := mng.GetUser("test@mail.com")
		if err != nil {
			t.Fatal(err)
		}
		ok, _ := hashutil.VerifyPassword("12345", u.HashPw)
		if ok {
			t.Errorf("expecting login failure for wrong password")
		}
	})

	t.Run("assert wrong user name", func(t *testing.T) {
		_, err := mng.GetUser("test_@mail.com")
		if err == nil {
			t.Errorf("expecting error for unknown user")
		}
	})
}

func TestCreateUserWithHashedPassword(t *testing.T) {
	mng := setup(t)
	defer clean()

	hashedPw, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	err = mng.CreateUserWithHashedPassword(User{
		LoginID: "alice",
		Pw:      string(hashedPw),
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	got, err := mng.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := hashutil.VerifyPassword("secret", got.HashPw)
	if err != nil || !ok {
		t.Errorf("password verification failed: ok=%v err=%v", ok, err)
	}
}

func TestSetPasswordHash(t *testing.T) {
	mng := setup(t)
	defer clean()

	err := mng.Create("bob", "original")
	if err != nil {
		t.Fatalf("unexpected error creating user: %s", err)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("updated"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	err = mng.SetPasswordHash("bob", string(newHash))
	if err != nil {
		t.Fatalf("unexpected error setting password hash: %s", err)
	}

	got, err := mng.GetUser("bob")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := hashutil.VerifyPassword("updated", got.HashPw)
	if err != nil || !ok {
		t.Errorf("password verification with new hash failed: ok=%v err=%v", ok, err)
	}

	// Verify old password no longer works
	ok, _ = hashutil.VerifyPassword("original", got.HashPw)
	if ok {
		t.Errorf("old password should not verify after hash update")
	}
}
