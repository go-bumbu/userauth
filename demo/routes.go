package main

import (
	"embed"
	"html/template"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
)

//go:embed files/*
var embedFs embed.FS

var demoUsers = staticusers.Users{
	Users: []staticusers.User{
		{Id: "admin", HashPw: userauth.MustHashPw("admin"), Enabled: true},
		{Id: "demo", HashPw: userauth.MustHashPw("demo"), Enabled: true},
	},
}

func demoHandler() http.Handler {

	r := mux.NewRouter()

	// ===============================================
	// Basicauth — see basicauth.go
	// ===============================================
	r.PathPrefix("/basic/").Handler(http.StripPrefix("/basic", basicAuthDemo()))

	// ===============================================
	// Password form login (cookie session) — see passwordlogin.go
	// ===============================================
	r.PathPrefix("/cookie/").Handler(http.StripPrefix("/cookie", cookieAuthDemo()))

	// ===============================================
	// Header auth — see headerauth.go
	// ===============================================
	r.PathPrefix("/header/").Handler(http.StripPrefix("/header", headerAuthDemo()))

	// ===============================================
	// Passwordless email-code login — see emaillogin.go
	// ===============================================
	r.PathPrefix("/emailcode/").Handler(http.StripPrefix("/emailcode", emailCodeDemo()))

	// ===============================================
	// User management — see users_admin.go
	// ===============================================
	r.PathPrefix("/users/").Handler(http.StripPrefix("/users", userMgmtDemo()))

	// ===============================================
	// User registration — see register_password.go, register_email.go
	// ===============================================
	r.Path("/register").Methods(http.MethodGet, http.MethodPost).HandlerFunc(registerHandler)
	r.Path("/register/email").Methods(http.MethodGet, http.MethodPost).HandlerFunc(registerEmailHandler)
	r.Path("/register/email/verify").Methods(http.MethodGet, http.MethodPost).HandlerFunc(registerEmailVerifyHandler)

	// ===============================================
	// User profile (self-service) — see profile.go
	// ===============================================
	r.PathPrefix("/profile/").Handler(http.StripPrefix("/profile", profileDemo()))

	// ===============================================
	// rest of the pages
	// ===============================================

	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		renderTmpl(writer, request, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(faviconHandler)

	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTmpl(w, r, "index.tmpl.html", nil)
	})
	return r
}

func renderTmpl(w http.ResponseWriter, r *http.Request, file string, data map[string]any) {
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

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}

}

func protectedPage(text string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTmpl(w, r, "protected.tmpl.html", map[string]any{"text": text})
	})
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	favicon, err := embedFs.Open(filepath.Join("files", "favicon.ico"))
	if err != nil {
		http.Error(w, "Favicon not found", http.StatusNotFound)
		return
	}
	defer func() {
		_ = favicon.Close()
	}()

	w.Header().Set("Content-Type", "image/x-icon")

	if _, err := io.Copy(w, favicon); err != nil {
		http.Error(w, "Failed to serve favicon", http.StatusInternalServerError)
		return
	}

}
