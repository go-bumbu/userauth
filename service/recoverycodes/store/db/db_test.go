package db

import (
	"testing"

	"github.com/go-bumbu/userauth/service/recoverycodes"
	"github.com/go-bumbu/userauth/service/recoverycodes/storetest"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := New(gdb)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) recoverycodes.Store {
		return newStore(t)
	})
}

func TestPurgeUser(t *testing.T) {
	s := newStore(t)
	if err := s.Replace("u1", []string{"h1", "h2"}); err != nil {
		t.Fatalf("Replace u1: %v", err)
	}
	if err := s.Replace("u2", []string{"h3"}); err != nil {
		t.Fatalf("Replace u2: %v", err)
	}

	if err := s.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if n, err := s.Count("u1"); err != nil || n != 0 {
		t.Errorf("u1 count after purge = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := s.Count("u2"); err != nil || n != 1 {
		t.Errorf("u2 count after purging u1 = (%d, %v), want (1, nil)", n, err)
	}
}

func TestNewWithClosedConnection(t *testing.T) {
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get underlying DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close connection: %v", err)
	}

	_, err = New(gdb)
	if err == nil {
		t.Fatal("New with closed connection: got nil error, want non-nil")
	}
}

func TestReplaceWithMissingTable(t *testing.T) {
	s := newStore(t)
	if err := s.db.Migrator().DropTable(&recoveryCodeModel{}); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	err := s.Replace("u1", []string{"h1"})
	if err == nil {
		t.Fatal("Replace with missing table: got nil error, want non-nil")
	}
}

func TestHashesWithMissingTable(t *testing.T) {
	s := newStore(t)
	if err := s.db.Migrator().DropTable(&recoveryCodeModel{}); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	_, err := s.Hashes("u1")
	if err == nil {
		t.Fatal("Hashes with missing table: got nil error, want non-nil")
	}
}
