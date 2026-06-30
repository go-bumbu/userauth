package main

import (
	"net/http"
	"strings"
)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTmpl(w, r, "register.tmpl.html", nil)
		return
	}

	login := strings.TrimSpace(r.FormValue("login"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if login == "" || password == "" {
		renderTmpl(w, r, "register.tmpl.html", map[string]any{
			"Error": "Login and password are required.",
			"Login": login,
		})
		return
	}

	if password != confirm {
		renderTmpl(w, r, "register.tmpl.html", map[string]any{
			"Error": "Passwords do not match.",
			"Login": login,
		})
		return
	}

	if err := dbUserMgr.Create(login, password); err != nil {
		renderTmpl(w, r, "register.tmpl.html", map[string]any{
			"Error": err.Error(),
			"Login": login,
		})
		return
	}

	userIDs = append(userIDs, login)
	renderTmpl(w, r, "register.tmpl.html", map[string]any{
		"Success": "User \"" + login + "\" registered successfully.",
	})
}
