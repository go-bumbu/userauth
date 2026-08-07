package web

import (
	"embed"
	"html/template"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed files/*
var embedFs embed.FS

// Renderer renders the demo's embedded server-side templates and static assets.
type Renderer struct{}

// New returns a Renderer over the embedded files/ directory.
func New() *Renderer { return &Renderer{} }

// Render parses and executes the named template from files/ with the given data.
func (rd *Renderer) Render(w http.ResponseWriter, _ *http.Request, file string, data map[string]any) {
	tmpl, err := template.ParseFS(embedFs, filepath.Join("files", file))
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(file, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(file, ".css") {
		w.Header().Set("Content-Type", "text/css")
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// ProtectedPage returns a handler that renders protected.tmpl.html with the given text.
func (rd *Renderer) ProtectedPage(text string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd.Render(w, r, "protected.tmpl.html", map[string]any{"text": text})
	})
}

// Favicon serves the embedded favicon.ico.
func (rd *Renderer) Favicon(w http.ResponseWriter, _ *http.Request) {
	favicon, err := embedFs.Open(filepath.Join("files", "favicon.ico"))
	if err != nil {
		http.Error(w, "Favicon not found", http.StatusNotFound)
		return
	}
	defer func() { _ = favicon.Close() }()
	w.Header().Set("Content-Type", "image/x-icon")
	if _, err := io.Copy(w, favicon); err != nil {
		http.Error(w, "Failed to serve favicon", http.StatusInternalServerError)
		return
	}
}
