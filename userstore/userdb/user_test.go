package userdb

import (
	"testing"

	"github.com/go-bumbu/userauth/support/hashutil"
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

func TestList(t *testing.T) {
	mng := setup(t)
	defer clean()

	// empty store
	res, err := mng.List(ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 0 {
		t.Errorf("empty: want total 0, got %d", res.Total)
	}
	if len(res.Users) != 0 {
		t.Errorf("empty: want 0 users, got %d", len(res.Users))
	}

	ids := []string{"u1", "u2", "u3", "u4", "u5"}
	for _, id := range ids {
		if err := mng.Create(id, "pw"); err != nil {
			t.Fatal(err)
		}
	}

	// default limit returns all five, ordered by login_id, total = 5
	res, err = mng.List(ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 5 {
		t.Errorf("default: want total 5, got %d", res.Total)
	}
	if len(res.Users) != 5 {
		t.Fatalf("default: want 5 users, got %d", len(res.Users))
	}
	for i, want := range ids {
		if res.Users[i].Id != want {
			t.Errorf("default order: index %d want %q, got %q", i, want, res.Users[i].Id)
		}
	}

	// page 1 of size 2
	res, _ = mng.List(ListOpts{Limit: 2, Offset: 0})
	if res.Total != 5 {
		t.Errorf("page1: want total 5, got %d", res.Total)
	}
	if len(res.Users) != 2 || res.Users[0].Id != "u1" || res.Users[1].Id != "u2" {
		t.Errorf("page1: want [u1 u2], got %+v", res.Users)
	}

	// page 2 of size 2
	res, _ = mng.List(ListOpts{Limit: 2, Offset: 2})
	if len(res.Users) != 2 || res.Users[0].Id != "u3" || res.Users[1].Id != "u4" {
		t.Errorf("page2: want [u3 u4], got %+v", res.Users)
	}

	// offset past the end → empty (non-nil), total still 5
	res, _ = mng.List(ListOpts{Limit: 2, Offset: 10})
	if res.Total != 5 {
		t.Errorf("overflow: want total 5, got %d", res.Total)
	}
	if res.Users == nil || len(res.Users) != 0 {
		t.Errorf("overflow: want empty non-nil slice, got %+v", res.Users)
	}

	// negative offset behaves like 0
	res, _ = mng.List(ListOpts{Limit: 1, Offset: -3})
	if len(res.Users) != 1 || res.Users[0].Id != "u1" {
		t.Errorf("negative offset: want [u1], got %+v", res.Users)
	}
}
