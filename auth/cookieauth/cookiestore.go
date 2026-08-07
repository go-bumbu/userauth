package cookieauth

import (
	"fmt"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// NewFsStore is a convenience function to generate a new session store that stores data on filesystem.
// It uses a secure cookie to keep the session id.
func NewFsStore(path string, HashKey, BlockKey []byte) (*sessions.FilesystemStore, error) {
	hashL := len(HashKey)
	if hashL != 32 && hashL != 64 {
		return nil, fmt.Errorf("HashKey length should be 32 or 64 bytes")
	}
	blockKeyL := len(BlockKey)
	if blockKeyL != 16 && blockKeyL != 24 && blockKeyL != 32 {
		return nil, fmt.Errorf("blockKey length should be 16, 24 or 32 bytes")
	}
	fsStore := sessions.NewFilesystemStore(path, HashKey, BlockKey)
	return fsStore, nil
}

// NewCookieStore creates a new cookie store with the given keys.
func NewCookieStore(HashKey, BlockKey []byte) (*sessions.CookieStore, error) {
	hashL := len(HashKey)
	if hashL != 32 && hashL != 64 {
		return nil, fmt.Errorf("HashKey length should be 32 or 64 bytes")
	}
	blockKeyL := len(BlockKey)
	if blockKeyL != 16 && blockKeyL != 24 && blockKeyL != 32 {
		return nil, fmt.Errorf("blockKey length should be 16, 24 or 32 bytes")
	}

	cs := &sessions.CookieStore{
		Codecs: securecookie.CodecsFromPairs(HashKey, BlockKey),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 30,
			SameSite: http.SameSiteNoneMode,
			HttpOnly: true,
			Secure:   true,
		},
	}
	cs.MaxAge(cs.Options.MaxAge)
	return cs, nil
}
