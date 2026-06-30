package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/examples"
	"github.com/go-bumbu/userauth/demo/router"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/staticusers"
)

func main() {
	logger := newLogger()

	users, err := examples.SeededStore()
	if err != nil {
		panic(fmt.Errorf("init store: %w", err))
	}

	staticUsers := &staticusers.Users{Users: []staticusers.User{
		{Id: "admin", HashPw: userauth.MustHashPw("admin"), Enabled: true},
		{Id: "demo", HashPw: userauth.MustHashPw("demo"), Enabled: true},
	}}

	handler := router.New(router.Cfg{
		Logger:      logger,
		Users:       users,
		StaticUsers: staticUsers,
		Web:         web.New(),
	})

	srv := &http.Server{Addr: ":8084", Handler: handler} // #nosec G112 -- demo server
	go func() {
		logger.Info("Server is running on port http://localhost:8084")
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
