// Package demotest holds helpers shared by the demo example tests: a silent
// logger, the template renderer, form posting, and a seeded in-memory user DB.
package demotest

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
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

// NewStores returns the full in-memory SQLite setup seeded with SeedAccounts.
func NewStores() (preset.Stores, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return preset.Stores{}, fmt.Errorf("open in-memory sqlite: %w", err)
	}
	s, err := preset.Full(db, userdb.Opts{
		BcryptDifficulty: 4,
		DefaultEnabled:   true,
	})
	if err != nil {
		return preset.Stores{}, fmt.Errorf("create db stores: %w", err)
	}
	for _, a := range SeedAccounts {
		if err := s.Users.Create(a.ID, a.Pw); err != nil {
			return preset.Stores{}, fmt.Errorf("seed user %s: %w", a.ID, err)
		}
	}
	return s, nil
}

// NewUserStore returns only the user store of NewStores, for examples that need
// nothing else.
func NewUserStore() (*userdb.Store, error) {
	s, err := NewStores()
	if err != nil {
		return nil, err
	}
	return s.Users, nil
}
