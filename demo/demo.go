package main

import (
	"embed"
	"fmt"
	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/authenticator"
	"github.com/go-bumbu/userauth/handlers/basicauth"
	"github.com/go-bumbu/userauth/handlers/headerauth"
	"github.com/go-bumbu/userauth/handlers/sessionauth"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"html/template"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
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
	basicAuthHandler := basicauth.NewHandler(loginHandler, "", true, logger)
	demoAuth1 := authenticator.New([]authenticator.AuthHandler{basicAuthHandler}, logger, nil, nil)
	basicProtected.Use(demoAuth1.Middleware)

	// ===============================================
	// cookie based session authentication
	// ===============================================
	cookieProtected := r.Path("/cookie-protected").Methods(http.MethodGet).Subrouter()
	cookieProtected.HandleFunc("", func(writer http.ResponseWriter, request *http.Request) {
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
	sessionAuthHandler, err := sessionauth.New(sessionauth.Cfg{
		Store:         sesStore,
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
	})
	if err != nil {
		panic("error instantiating sessionauth")
	}
	demoAuth2 := authenticator.New([]authenticator.AuthHandler{sessionAuthHandler}, logger, nil, nil)
	cookieProtected.Use(demoAuth2.Middleware)

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
	// Header Auth
	// ===============================================

	hauth := headerauth.New(headerauth.UserAuthHeader, true, logger)

	headerProtected := r.Path("/header-protected").Methods(http.MethodGet).Subrouter()
	headerProtected.HandleFunc("", func(writer http.ResponseWriter, request *http.Request) {
		data := hauth.GetData(request)
		renderTmpl(writer, request, "protected.tmpl.html", map[string]any{
			"text": fmt.Sprintf("content protected by the presence of the header X-User-Auth with value: %s", data.UserName),
		})
	})

	headerProtected.Use(hauth.Middleware)

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

		expire := time.Until(sessData.Expiration).Round(time.Second).String()
		forceExpire := time.Until(sessData.Expiration).Round(time.Second).String()

		data := map[string]any{
			"LoggedIn":     sessData.IsAuthenticated,
			"user":         sessData.UserId,
			"expiration":   expire,
			"forceExpire":  forceExpire,
			"sessionRenew": sessData.RenewExpiration,
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
	defer func() {
		_ = favicon.Close()
	}()

	// Set the Content-Type header
	w.Header().Set("Content-Type", "image/x-icon")

	// Copy the file content to the response
	if _, err := io.Copy(w, favicon); err != nil {
		http.Error(w, "Failed to serve favicon", http.StatusInternalServerError)
		return
	}

}
