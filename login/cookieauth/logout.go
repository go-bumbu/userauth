package cookieauth

import (
	"net/http"

	"github.com/go-bumbu/userauth/auth/cookieauth"
)

// LogoutHandler returns an HTTP handler that destroys the session and optionally redirects.
func LogoutHandler(sessMgr *cookieauth.Manager, redirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := sessMgr.LogoutUser(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	})
}
