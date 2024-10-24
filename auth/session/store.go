package session

import (
	"fmt"

	"github.com/gorilla/sessions"
)

// NewFsStore is a convenience function to generate a new  File system store
// is uses a secure cookie to keep the session id
func NewFsStore(path string, HashKey, BlockKey []byte) (*sessions.FilesystemStore, error) {
	hashL := len(HashKey)
	if hashL != 32 && hashL != 64 {
		return nil, fmt.Errorf("HashKey lenght should be 32 or 64 bytes")
	}
	blockKeyL := len(BlockKey)
	if blockKeyL != 16 && blockKeyL != 24 && blockKeyL != 32 {
		return nil, fmt.Errorf("blockKey lenght should be 16, 24 or 32 bytes")
	}
	fsStore := sessions.NewFilesystemStore(path, HashKey, BlockKey)
	// fsStore.MaxAge() TODO set max age of store

	return fsStore, nil
}
