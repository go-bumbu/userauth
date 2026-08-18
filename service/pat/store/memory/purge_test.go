package memory

import (
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
)

func TestPurgeUser(t *testing.T) {
	s := New()
	rec1 := pat.TokenRecord{TokenID: "t1", UserID: "u1", SecretHash: "h1"}
	rec2 := pat.TokenRecord{TokenID: "t2", UserID: "u1", SecretHash: "h2"}
	rec3 := pat.TokenRecord{TokenID: "t3", UserID: "u2", SecretHash: "h3"}

	if err := s.Insert(rec1); err != nil {
		t.Fatalf("Insert t1: %v", err)
	}
	if err := s.Insert(rec2); err != nil {
		t.Fatalf("Insert t2: %v", err)
	}
	if err := s.Insert(rec3); err != nil {
		t.Fatalf("Insert t3: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if list, _ := s.ListByUser("u1"); len(list) != 0 {
		t.Errorf("u1 still has %d tokens after purge, want 0", len(list))
	}
	if list, _ := s.ListByUser("u2"); len(list) != 1 {
		t.Errorf("u2 has %d tokens, want 1", len(list))
	}
}
