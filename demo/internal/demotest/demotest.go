// Package demotest holds helpers shared by the demo example tests: a silent
// logger, the template renderer, form posting, and a seeded in-memory user DB.
package demotest

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Logger returns a logger that discards all output.
func Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Web returns the demo template renderer.
func Web() *web.Renderer { return web.New() }

// PostForm posts a urlencoded form to handler, attaching cookies.
func PostForm(handler http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// SeedAccounts are the users NewUserStore creates.
var SeedAccounts = []struct{ ID, Pw string }{
	{"admin", "admin"},
	{"demo", "demo"},
	{"admin@example.com", "admin"},
	{"demo@example.com", "demo"},
}

// NewUserStore returns an in-memory SQLite userdb.Store seeded with SeedAccounts.
func NewUserStore() (*userdb.Store, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open in-memory sqlite: %w", err)
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		return nil, fmt.Errorf("generate TOTP encryption key: %w", err)
	}
	mgr, err := userdb.New(db, userdb.Opts{
		BcryptDifficulty:  4,
		DefaultEnabled:    true,
		TOTPEncryptionKey: totpKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create db store: %w", err)
	}
	for _, a := range SeedAccounts {
		if err := mgr.Create(a.ID, a.Pw); err != nil {
			return nil, fmt.Errorf("seed user %s: %w", a.ID, err)
		}
	}
	return mgr, nil
}
