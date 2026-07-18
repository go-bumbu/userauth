package examples

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/go-bumbu/userauth/demo/web"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testWeb() *web.Renderer { return web.New() }

// postForm posts a urlencoded form to handler, attaching cookies.
func postForm(handler http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}
