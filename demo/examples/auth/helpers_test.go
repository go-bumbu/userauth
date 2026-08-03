package auth

import (
	"io"
	"log/slog"

	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"golang.org/x/crypto/bcrypt"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testWeb() *web.Renderer { return web.New() }

func mustHash(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}

// staticDemoUsers returns the admin/demo static credentials used by the auth examples.
func staticDemoUsers() *staticusers.Users {
	return &staticusers.Users{Users: []staticusers.User{
		{Id: "admin", HashPw: mustHash("admin"), Enabled: true},
		{Id: "demo", HashPw: mustHash("demo"), Enabled: true},
	}}
}
