package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDeliver_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	exp := time.Now().UTC().Add(15 * time.Minute)
	err = d.Deliver(context.Background(), "user@example.com", "123456", exp)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(len(entries), 1); diff != "" {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}

	content, err := os.ReadFile(filepath.Join(dir, entries[0].Name())) //nolint:gosec // reading from t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	body := string(content)
	if !strings.Contains(body, "user@example.com") {
		t.Errorf("file should contain recipient, got: %s", body)
	}
	if !strings.Contains(body, "123456") {
		t.Errorf("file should contain code, got: %s", body)
	}
}

func TestDeliver_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = d.Deliver(context.Background(), "test@test.com", "999999", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(len(entries), 1); diff != "" {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
}

func TestDeliver_SanitizesRecipient(t *testing.T) {
	dir := t.TempDir()
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = d.Deliver(context.Background(), "user/../etc/passwd", "000000", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(len(entries), 1); diff != "" {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	// file must be in dir, not escaped via path traversal
	name := entries[0].Name()
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		t.Errorf("filename should be sanitized, got: %s", name)
	}
}

func TestDeliver_MultipleDeliveries(t *testing.T) {
	dir := t.TempDir()
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		code := strings.Repeat(string(rune('1'+i)), 6)
		err = d.Deliver(context.Background(), "user@example.com", code, time.Now().Add(15*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(len(entries), 3); diff != "" {
		t.Fatalf("expected 3 files, got %d", len(entries))
	}
}
