package main

import (
	"embed"
	"fmt"
	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/authenticator"
	"github.com/go-bumbu/userauth/handlers/basicauth"
	"github.com/go-bumbu/userauth/handlers/sessionauth"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// login handler uses a user store to handle loging
	loginHandler := userauth.LoginHandler{
		UserStore: &demoUsers,
	}

	// ===============================================
	// Basicauth
	// ===============================================
	basicProtected := r.Path("/basic").Methods(http.MethodGet).Subrouter()
	basicProtected.HandleFunc("", func(writer http.ResponseWriter, request *http.Request) {
		renderTmpl(writer, request, "protected.tmpl.html", map[string]any{
			"text": "content protected by basicauth only",
		})
	})
	basicAuthHandler := basicauth.NewHandler(loginHandler, "", true, log)
	demoAuth1 := authenticator.New([]authenticator.AuthHandler{basicAuthHandler}, log, nil, nil)
	basicProtected.Use(demoAuth1.Middleware)

	// ===============================================
	// cookie based session authentication
	// ===============================================
	apiRouter := r.Path("/protected").Methods(http.MethodGet).Subrouter()
	apiRouter.HandleFunc("", func(writer http.ResponseWriter, request *http.Request) {
		renderTmpl(writer, request, "protected.tmpl.html", map[string]any{
			"text": "content protected by session cookie",
		})
	})

	// instantiate a session store, note this will use a new encryption key every start
	// in the real world you want to have them periodically rotated, changing the keys will invalidate existing cookies
	sesStore, err := sessionauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("error instantiating fsstore: %v", err))
	}

	// instantiate a session handler with the session store
	sessionAuthHandler, err := sessionauth.New(sessionauth.Cfg{Store: sesStore})
	if err != nil {
		panic("error instantiating sessionauth")
	}
	demoAuth2 := authenticator.New([]authenticator.AuthHandler{sessionAuthHandler}, log, nil, nil)
	apiRouter.Use(demoAuth2.Middleware)

	// ===============================================
	// session login/logout
	// ===============================================
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		renderTmpl(writer, request, "login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).Handler(
		sessionAuthHandler.FormAuthHandler(loginHandler, "/"))
	r.Path("/logout").Handler(
		sessionAuthHandler.LogoutHandler("/"))

	// ===============================================
	// rest of the pages
	// ===============================================

	r.Path("/styles.css").Methods(http.MethodGet).HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		renderTmpl(writer, request, "styles.css", nil)
	})
	r.Path("/favicon.ico").Methods(http.MethodGet).HandlerFunc(faviconHandler)

	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessData, err := sessionAuthHandler.GetSessData(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data := map[string]any{
			"LoggedIn": sessData.IsAuthenticated,
			"user":     sessData.UserId,
		}
		renderTmpl(w, r, "index.tmpl.html", data)
	})
	return r
}

func renderTmpl(w http.ResponseWriter, r *http.Request, file string, data map[string]any) {
	// Parse the template from the embedded filesystem

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

	// Execute the template and write the response
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}

}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	favicon, err := embedFs.Open(filepath.Join("files", "favicon.ico"))
	if err != nil {
		http.Error(w, "Favicon not found", http.StatusNotFound)
		return
	}
	defer favicon.Close()

	// Set the Content-Type header
	w.Header().Set("Content-Type", "image/x-icon")

	// Copy the file content to the response
	if _, err := io.Copy(w, favicon); err != nil {
		http.Error(w, "Failed to serve favicon", http.StatusInternalServerError)
		return
	}

}
