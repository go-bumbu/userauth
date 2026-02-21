package cookieauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/cookieauth"
)

// FormAuthHandler returns an HTTP handler that accepts form POST login (username, password, session_renew)
// and establishes a session on success.
func FormAuthHandler(sessMgr *cookieauth.Manager, auth *userauth.LoginHandler, redirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusInternalServerError)
			return
		}

		userName := r.FormValue("username")
		userPw := r.FormValue("password")

		sessRen := false
		if r.FormValue("session_renew") == "on" {
			sessRen = true
		}

		result, err := auth.CanLogin(userName, userPw)
		if err != nil {
			switch {
			case errors.Is(err, userauth.ErrUserNotFound):
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			case errors.Is(err, userauth.ErrUserDisabled):
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			default:
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if result.Authenticated {
			userID := result.UserID
			if userID == "" {
				userID = userName
			}
			err = sessMgr.LoginUser(r, w, userID, sessRen)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if redirect != "" {
				http.Redirect(w, r, redirect, http.StatusSeeOther)
				return
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}
