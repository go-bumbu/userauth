package memory

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

func TestStoreAndConsume(t *testing.T) {
	s := New()
	hash := hashutil.HashCodeSHA256("123456")
	if err := s.StoreCode("user1", hash, time.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("StoreCode failed: %v", err)
	}
	ok, err := s.ConsumeCode("user1", hash, 5)
	if err != nil {
		t.Fatalf("ConsumeCode error: %v", err)
	}
	if !ok {
		t.Fatal("expected consume to succeed")
	}
}

func TestConsume_OneTime(t *testing.T) {
	s := New()
	hash := hashutil.HashCodeSHA256("123456")
	_ = s.StoreCode("user1", hash, time.Now().Add(15*time.Minute))

	if ok, _ := s.ConsumeCode("user1", hash, 5); !ok {
		t.Fatal("first consume should succeed")
	}
	if ok, _ := s.ConsumeCode("user1", hash, 5); ok {
		t.Fatal("second consume should fail — code consumed")
	}
}

func TestConsume_Expired(t *testing.T) {
	s := New()
	hash := hashutil.HashCodeSHA256("123456")
	_ = s.StoreCode("user1", hash, time.Now().Add(-1*time.Minute))

	if ok, _ := s.ConsumeCode("user1", hash, 5); ok {
		t.Fatal("expired code should not consume")
	}
}

func TestConsume_WrongHash(t *testing.T) {
	s := New()
	_ = s.StoreCode("user1", hashutil.HashCodeSHA256("123456"), time.Now().Add(15*time.Minute))

	if ok, _ := s.ConsumeCode("user1", hashutil.HashCodeSHA256("000000"), 5); ok {
		t.Fatal("wrong hash should not consume")
	}

	// A wrong attempt must not consume the still-valid code.
	if ok, _ := s.ConsumeCode("user1", hashutil.HashCodeSHA256("123456"), 5); !ok {
		t.Fatal("correct code should still consume after a wrong attempt")
	}
}

func TestConsume_UnknownUser(t *testing.T) {
	s := New()
	if ok, _ := s.ConsumeCode("nobody", hashutil.HashCodeSHA256("123456"), 5); ok {
		t.Fatal("unknown user should not consume")
	}
}

func TestConsume_AttemptsExhausted(t *testing.T) {
	s := New()
	hash := hashutil.HashCodeSHA256("123456")
	wrong := hashutil.HashCodeSHA256("000000")
	_ = s.StoreCode("user1", hash, time.Now().Add(15*time.Minute))

	for i := 0; i < 3; i++ {
		if ok, _ := s.ConsumeCode("user1", wrong, 3); ok {
			t.Fatal("wrong hash should not consume")
		}
	}
	if ok, _ := s.ConsumeCode("user1", hash, 3); ok {
		t.Fatal("correct code should be invalid after attempts are exhausted")
	}
}

func TestStoreCode_ResetsAttempts(t *testing.T) {
	s := New()
	hash := hashutil.HashCodeSHA256("123456")
	wrong := hashutil.HashCodeSHA256("000000")
	_ = s.StoreCode("user1", hash, time.Now().Add(15*time.Minute))

	_, _ = s.ConsumeCode("user1", wrong, 3)
	_, _ = s.ConsumeCode("user1", wrong, 3)

	// Re-issuing replaces the code and its attempt count.
	hash2 := hashutil.HashCodeSHA256("222222")
	_ = s.StoreCode("user1", hash2, time.Now().Add(15*time.Minute))
	_, _ = s.ConsumeCode("user1", wrong, 3)
	if ok, _ := s.ConsumeCode("user1", hash2, 3); !ok {
		t.Fatal("new code should consume — attempts reset on re-issue")
	}
}

func TestStoreCode_OverwritesPrevious(t *testing.T) {
	s := New()
	hash1 := hashutil.HashCodeSHA256("111111")
	hash2 := hashutil.HashCodeSHA256("222222")
	_ = s.StoreCode("user1", hash1, time.Now().Add(15*time.Minute))
	_ = s.StoreCode("user1", hash2, time.Now().Add(15*time.Minute))

	if ok, _ := s.ConsumeCode("user1", hash1, 5); ok {
		t.Fatal("old code should not consume after overwrite")
	}
	if ok, _ := s.ConsumeCode("user1", hash2, 5); !ok {
		t.Fatal("new code should consume")
	}
}
