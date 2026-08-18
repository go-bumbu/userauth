package memory

import (
	"testing"
	"time"
)

func TestPurgeUser(t *testing.T) {
	s := New()
	future := time.Now().Add(10 * time.Minute)

	if err := s.StoreCode("u1", "hash1", future); err != nil {
		t.Fatalf("StoreCode u1: %v", err)
	}
	if err := s.StoreCode("u2", "hash2", future); err != nil {
		t.Fatalf("StoreCode u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if ok, _ := s.ConsumeCode("u1", "hash1", 5); ok {
		t.Error("u1's code still works after purge")
	}
	if ok, _ := s.ConsumeCode("u2", "hash2", 5); !ok {
		t.Error("u2's code was affected by u1's purge")
	}
}
