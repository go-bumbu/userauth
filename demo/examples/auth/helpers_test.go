package auth

import (
	"io"
	"log/slog"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/staticusers"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testWeb() *web.Renderer { return web.New() }

// staticDemoUsers returns the admin/demo static credentials used by the auth examples.
func staticDemoUsers() *staticusers.Users {
	return &staticusers.Users{Users: []staticusers.User{
		{Id: "admin", HashPw: userauth.MustHashPw("admin"), Enabled: true},
		{Id: "demo", HashPw: userauth.MustHashPw("demo"), Enabled: true},
	}}
}
