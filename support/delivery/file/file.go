package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// sanitize replaces characters unsafe for filenames.
var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9@._+-]`)

// Deliverer writes verification codes to files on disk. Each call to Deliver
// creates a new file in dir. Intended for development and testing.
type Deliverer struct {
	dir string
}

// New returns a Deliverer that writes files to dir.
func New(dir string) (*Deliverer, error) {
	return &Deliverer{dir: dir}, nil
}

// Deliver writes a file containing the code and metadata.
func (d *Deliverer) Deliver(_ context.Context, to string, code string, expiresAt time.Time) error {
	if err := os.MkdirAll(d.dir, 0750); err != nil {
		return fmt.Errorf("file delivery: create dir: %w", err)
	}

	safe := unsafeChars.ReplaceAllString(to, "_")
	// Also ensure no .. sequences remain (path traversal attempts)
	safe = regexp.MustCompile(`\.\.`).ReplaceAllString(safe, "_")
	name := fmt.Sprintf("%d-%s.txt", time.Now().UnixNano(), safe)
	path := filepath.Join(d.dir, name)

	body := fmt.Sprintf("to: %s\ncode: %s\nexpires: %s\n", to, code, expiresAt.UTC().Format(time.RFC3339))

	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		return fmt.Errorf("file delivery: write: %w", err)
	}
	return nil
}
