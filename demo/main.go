package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	"github.com/go-bumbu/userauth/demo/router"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	logger := newLogger()

	stores, err := newStores()
	if err != nil {
		panic(fmt.Errorf("init store: %w", err))
	}

	staticUsers := &staticusers.Users{Users: []staticusers.User{
		{Id: "admin", HashPw: userauth.MustHashPassword("admin"), Enabled: true},
		{Id: "demo", HashPw: userauth.MustHashPassword("demo"), Enabled: true},
	}}

	mfaSvc, err := mfa.New(logger, stores)
	if err != nil {
		panic(fmt.Errorf("init second factors: %w", err))
	}

	handler := router.New(router.Cfg{
		Logger:      logger,
		Stores:      stores,
		MFA:         mfaSvc,
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

var demoSeedAccounts = []struct{ id, pw string }{
	{"admin", "admin"},
	{"demo", "demo"},
	{"admin@example.com", "admin"},
	{"demo@example.com", "demo"},
}

func newStores() (preset.Stores, error) {
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
	for _, a := range demoSeedAccounts {
		if err := s.Users.Create(a.id, a.pw); err != nil {
			return preset.Stores{}, fmt.Errorf("seed user %s: %w", a.id, err)
		}
	}
	return s, nil
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
