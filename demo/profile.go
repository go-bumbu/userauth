package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/hashutil"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

var profileSessMgr *cookieauth.Manager

func profileDemo() http.Handler {
	r := mux.NewRouter()

	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("profile: error instantiating cookie store: %v", err))
	}

	profileSessMgr, err = cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_profile_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        logger,
	})
	if err != nil {
		panic("profile: error instantiating session manager")
	}

	profileLogin = userauth.LoginHandler{
		UserStore:     dbUserMgr,
		SecondFactors: dbUserMgr,
		TOTP:          dbUserMgr,
		RecoveryCode:  dbUserMgr,
	}

	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTmpl(w, r, "profile_login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(profileLoginHandler)
	r.Path("/login/2fa").Methods(http.MethodPost).HandlerFunc(profile2FAHandler)
	r.Path("/logout").Handler(
		logincookie.LogoutHandler(profileSessMgr, "/"))

	r.Path("/").Methods(http.MethodGet).Handler(requireProfileAuth(http.HandlerFunc(profileViewHandler)))
	r.Path("/change-password").Methods(http.MethodPost).Handler(requireProfileAuth(http.HandlerFunc(profileChangePasswordHandler)))
	r.Path("/change-email").Methods(http.MethodPost).Handler(requireProfileAuth(http.HandlerFunc(profileChangeEmailHandler)))

	return r
}

func requireProfileAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := profileSessMgr.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/profile/login", http.StatusSeeOther)
	})
}

func profileViewHandler(w http.ResponseWriter, r *http.Request) {
	profileViewWithMsg(w, r, "", "")
}

func profileViewWithMsg(w http.ResponseWriter, r *http.Request, success, errMsg string) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	user, err := dbUserMgr.GetUser(ud.UserId)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}
	renderTmpl(w, r, "profile.tmpl.html", map[string]any{
		"UserID":  user.Id,
		"Email":   user.PrimaryEmail,
		"Enabled": user.Enabled,
		"Success": success,
		"Error":   errMsg,
	})
}

func profileChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if strings.TrimSpace(current) == "" || strings.TrimSpace(newPw) == "" {
		profileViewWithMsg(w, r, "", "Current and new passwords are required.")
		return
	}
	if newPw != confirm {
		profileViewWithMsg(w, r, "", "New passwords do not match.")
		return
	}

	user, err := dbUserMgr.GetUser(ud.UserId)
	if err != nil {
		profileViewWithMsg(w, r, "", "Could not load user.")
		return
	}
	ok, err := hashutil.VerifyPassword(current, user.HashPw)
	if err != nil || !ok {
		profileViewWithMsg(w, r, "", "Current password is incorrect.")
		return
	}

	hashed, err := hashutil.HashPassword(newPw)
	if err != nil {
		profileViewWithMsg(w, r, "", "Could not hash password.")
		return
	}
	if err := dbUserMgr.SetPasswordHash(ud.UserId, hashed); err != nil {
		profileViewWithMsg(w, r, "", "Could not update password: "+err.Error())
		return
	}
	profileViewWithMsg(w, r, "Password updated successfully.", "")
}

func profileChangeEmailHandler(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		profileViewWithMsg(w, r, "", "Email address is required.")
		return
	}

	if err := dbUserMgr.SetPrimaryEmail(ud.UserId, email); err != nil {
		profileViewWithMsg(w, r, "", "Could not update email: "+err.Error())
		return
	}
	profileViewWithMsg(w, r, "Email updated successfully.", "")
}
