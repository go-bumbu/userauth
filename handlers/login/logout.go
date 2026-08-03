// Package login provides session logout. Login flows (password, multi-factor,
// passwordless email code) live in the loginflow package and its transports.
package login

import "net/http"

// UserLogout destroys an existing session.
// authhandler/cookieauth.Manager satisfies this implicitly.
type UserLogout interface {
	LogoutUser(r *http.Request, w http.ResponseWriter) error
}

// LogoutHandler returns an HTTP handler that destroys the session and optionally redirects.
func LogoutHandler(LogOuter UserLogout, redirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := LogOuter.LogoutUser(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	})
}
