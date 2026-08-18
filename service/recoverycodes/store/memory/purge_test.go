package memory

import "testing"

func TestPurgeUser(t *testing.T) {
	s := New()
	if err := s.Replace("u1", []string{"hash1", "hash2"}); err != nil {
		t.Fatalf("Replace u1: %v", err)
	}
	if err := s.Replace("u2", []string{"hash3"}); err != nil {
		t.Fatalf("Replace u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if n, _ := s.Count("u1"); n != 0 {
		t.Errorf("u1 still has %d codes after purge, want 0", n)
	}
	if n, _ := s.Count("u2"); n != 1 {
		t.Errorf("u2 has %d codes, want 1", n)
	}
}
