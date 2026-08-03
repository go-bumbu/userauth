package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-bumbu/userauth/demo/router"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	logger := newLogger()

	users, err := newUserStore()
	if err != nil {
		panic(fmt.Errorf("init store: %w", err))
	}

	staticUsers := &staticusers.Users{Users: []staticusers.User{
		{Id: "admin", HashPw: mustHashPw("admin"), Enabled: true},
		{Id: "demo", HashPw: mustHashPw("demo"), Enabled: true},
	}}

	handler := router.New(router.Cfg{
		Logger:      logger,
		Users:       users,
		StaticUsers: staticUsers,
		Web:         web.New(),
	})

	port := os.Getenv("DEMO_PORT")
	if port == "" {
		port = "8085"
	}
	srv := &http.Server{Addr: ":" + port, Handler: handler} // #nosec G112 -- demo server
	go func() {
		logger.Info("Server is running on http://localhost:" + port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan
	logger.Info("Signal received, shutting down...")
	_ = srv.Close()
}

// mustHashPw bcrypt-hashes a demo password; the static store holds hashes only.
func mustHashPw(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}

var demoSeedAccounts = []struct{ id, pw string }{
	{"admin", "admin"},
	{"demo", "demo"},
	{"admin@example.com", "admin"},
	{"demo@example.com", "demo"},
}

func newUserStore() (*userdb.Store, error) {
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
	for _, a := range demoSeedAccounts {
		if err := mgr.Create(a.id, a.pw); err != nil {
			return nil, fmt.Errorf("seed user %s: %w", a.id, err)
		}
	}
	return mgr, nil
}

func newLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05"))
			}
			return a
		},
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
