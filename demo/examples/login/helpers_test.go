package login

import (
	"io"
	"log/slog"

	"github.com/go-bumbu/userauth/demo/web"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testWeb() *web.Renderer { return web.New() }
