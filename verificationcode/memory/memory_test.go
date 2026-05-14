package memory

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/hashutil"
)

func TestStoreAndVerify(t *testing.T) {
	s := New()

	code := "123456"
	hash := hashutil.HashCodeSHA256(code)
	expires := time.Now().Add(15 * time.Minute)

	err := s.Store("user1", hash, expires)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	ok, err := s.VerifyEmailCode("user1", code)
	if err != nil {
		t.Fatalf("VerifyEmailCode error: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestVerify_ConsumesCode(t *testing.T) {
	s := New()

	code := "123456"
	hash := hashutil.HashCodeSHA256(code)
	expires := time.Now().Add(15 * time.Minute)
	_ = s.Store("user1", hash, expires)

	ok, _ := s.VerifyEmailCode("user1", code)
	if !ok {
		t.Fatal("first verify should succeed")
	}

	ok, _ = s.VerifyEmailCode("user1", code)
	if ok {
		t.Fatal("second verify should fail — code consumed")
	}
}

func TestVerify_Expired(t *testing.T) {
	s := New()

	code := "123456"
	hash := hashutil.HashCodeSHA256(code)
	expires := time.Now().Add(-1 * time.Minute) // already expired
	_ = s.Store("user1", hash, expires)

	ok, _ := s.VerifyEmailCode("user1", code)
	if ok {
		t.Fatal("expired code should not verify")
	}
}

func TestVerify_WrongCode(t *testing.T) {
	s := New()

	hash := hashutil.HashCodeSHA256("123456")
	expires := time.Now().Add(15 * time.Minute)
	_ = s.Store("user1", hash, expires)

	ok, _ := s.VerifyEmailCode("user1", "000000")
	if ok {
		t.Fatal("wrong code should not verify")
	}
}

func TestVerify_UnknownUser(t *testing.T) {
	s := New()

	ok, _ := s.VerifyEmailCode("nobody", "123456")
	if ok {
		t.Fatal("unknown user should not verify")
	}
}

func TestStore_OverwritesPrevious(t *testing.T) {
	s := New()

	hash1 := hashutil.HashCodeSHA256("111111")
	hash2 := hashutil.HashCodeSHA256("222222")
	expires := time.Now().Add(15 * time.Minute)

	_ = s.Store("user1", hash1, expires)
	_ = s.Store("user1", hash2, expires)

	ok, _ := s.VerifyEmailCode("user1", "111111")
	if ok {
		t.Fatal("old code should not verify after overwrite")
	}

	ok, _ = s.VerifyEmailCode("user1", "222222")
	if !ok {
		t.Fatal("new code should verify")
	}
}
