package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/login"
	pendingmemory "github.com/go-bumbu/userauth/pendinglogin/memory"
)

// profileLogin is built in profileDemo() (after dbUserMgr is initialised in usermgmt.go init()).
var profileLogin userauth.LoginHandler

// profilePendingLogins holds the pending second-factor state between the password step
// and the 2FA step. Demo-only: the memory store keys by userID and is not bound to the
// client; production would use pendinglogin/cookie or /db.
var profilePendingLogins = pendingmemory.New()

func profileLoginHandler(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	result, err := profileLogin.CanLogin(username, password)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) || errors.Is(err, userauth.ErrUserDisabled) {
			renderTmpl(w, r, "profile_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
			return
		}
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}

	if result.Authenticated {
		if err := profileSessMgr.LoginUser(r, w, result.UserID, false); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/profile/", http.StatusSeeOther)
		return
	}

	if result.Requires2FA {
		if err := profilePendingLogins.SetPendingLogin(r, w, login.PendingLogin{
			UserID:    result.UserID,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		renderTmpl(w, r, "profile_2fa.tmpl.html", map[string]any{"UserID": result.UserID})
		return
	}

	renderTmpl(w, r, "profile_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
}

func profile2FAHandler(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.FormValue("userID"))
	code := strings.TrimSpace(r.FormValue("code"))

	if _, err := profilePendingLogins.GetPendingLogin(r, userID); err != nil {
		renderTmpl(w, r, "profile_login.tmpl.html", map[string]any{
			"Error": "Login session expired, please log in again.",
		})
		return
	}

	res, _ := profileLogin.VerifyTOTP(userID, code)
	if !res.Authenticated {
		res, _ = profileLogin.VerifyRecoveryCode(userID, code)
	}
	if !res.Authenticated {
		renderTmpl(w, r, "profile_2fa.tmpl.html", map[string]any{
			"UserID": userID,
			"Error":  "Invalid code, try again.",
		})
		return
	}

	_ = profilePendingLogins.ClearPendingLogin(r, w, userID)
	if err := profileSessMgr.LoginUser(r, w, userID, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile/", http.StatusSeeOther)
}
