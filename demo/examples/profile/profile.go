// Package profile holds the demo example for an authenticated self-service
// area backed by userdb.Store: cookie-session password login with an optional
// TOTP second factor and recovery codes, plus password, email, and two-factor
// management.
package profile

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/flow/login"
	flowmemory "github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	"github.com/go-bumbu/userauth/flow/pat/handlers"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// app holds the dependencies shared by the profile handlers.
type app struct {
	log     *slog.Logger
	users   *userdb.Store
	mfa     mfa.Services
	rnd     *web.Renderer
	sessMgr *cookieauth.Manager
	flow    *login.Flow
	pats    *patsvc.Service
}

// New demonstrates an authenticated self-service area backed by the given GORM
// stores: cookie-session password login with an optional TOTP second factor and
// recovery codes, plus password, email, and two-factor management.
func New(log *slog.Logger, stores preset.Stores, mfaSvc mfa.Services, rnd *web.Renderer) http.Handler {
	users := stores.Users
	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("profile: error instantiating cookie store: %v", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_profile_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        log,
	})
	if err != nil {
		panic("profile: error instantiating session manager")
	}
	// password first; when the user has TOTP enabled, either an authenticator
	// code or a recovery code completes the login. A PolicyFunc is used
	// because the requirement is dynamic (per-user enrolment) and offers an
	// alternative (recovery) that is not a second factor in its own right.
	policy := login.PolicyFunc(func(user userauth.User, satisfied []string) (bool, []string, error) {
		if !slices.Contains(satisfied, login.MethodPassword) {
			return false, []string{login.MethodPassword}, nil
		}
		totpOn, err := mfaSvc.TOTP.Enabled(user.ID)
		if err != nil {
			return false, nil, err
		}
		if !totpOn ||
			slices.Contains(satisfied, login.MethodTOTP) ||
			slices.Contains(satisfied, login.MethodRecovery) {
			return true, nil, nil
		}
		return false, []string{login.MethodTOTP, login.MethodRecovery}, nil
	})

	pats, err := patsvc.NewService(stores.PATs, users, patsvc.Opts{Logger: log})
	if err != nil {
		panic(fmt.Errorf("profile: error creating PAT service: %v", err))
	}

	a := &app{
		log:     log,
		users:   users,
		mfa:     mfaSvc,
		rnd:     rnd,
		sessMgr: sessMgr,
		flow: &login.Flow{
			Users: users,
			Methods: []login.Method{
				login.PasswordMethod{Users: users},
				login.TOTPMethod{TOTP: mfaSvc.TOTP},
				login.RecoveryMethod{Codes: mfaSvc.Recovery},
			},
			Policy:   policy,
			Attempts: flowmemory.New(),
			Session:  sessMgr,
			Logger:   log,
		},
		pats: pats,
	}

	r := mux.NewRouter()
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.rnd.Render(w, req, "profile_login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(a.loginPost)
	r.Path("/login/2fa").Methods(http.MethodPost).HandlerFunc(a.verify2FA)
	r.Path("/logout").Handler(cookieauth.LogoutHandler(a.sessMgr, "/"))
	r.Path("/").Methods(http.MethodGet).Handler(a.requireAuth(http.HandlerFunc(a.view)))
	r.Path("/change-password").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.changePassword)))
	r.Path("/change-email").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.changeEmail)))
	r.Path("/totp/setup").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpSetup)))
	r.Path("/totp/qr.png").Methods(http.MethodGet).Handler(a.requireAuth(http.HandlerFunc(a.totpQR)))
	r.Path("/totp/confirm").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpConfirm)))
	r.Path("/totp/disable").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpDisable)))
	r.Path("/pat").Methods(http.MethodGet).Handler(a.requireAuth(http.HandlerFunc(a.patView)))
	r.Path("/pat/create").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.patCreate)))
	r.Path("/pat/revoke").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.patRevoke)))
	// JSON API for the same operations, e.g. for curl; same session auth
	patAPI := handlers.New(handlers.Cfg{Service: pats, Logger: log})
	r.Path("/pat/api").Methods(http.MethodPost).Handler(a.requireAuth(patAPI.CreateHandler()))
	r.Path("/pat/api").Methods(http.MethodGet).Handler(a.requireAuth(patAPI.ListHandler()))
	r.PathPrefix("/pat/api/").Methods(http.MethodDelete).Handler(a.requireAuth(patAPI.DeleteHandler()))
	return r
}

// requireAuth wraps a handler so unauthenticated requests are redirected to the login page.
func (a *app) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := a.sessMgr.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/profile/login", http.StatusSeeOther)
	})
}

// view renders the profile page.
func (a *app) view(w http.ResponseWriter, r *http.Request) {
	a.viewWithMsg(w, r, "", "")
}

// viewWithMsg renders the profile page with an optional success or error banner.
func (a *app) viewWithMsg(w http.ResponseWriter, r *http.Request, success, errMsg string) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	user, err := a.users.GetUser(ud.UserId)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}
	totpEnabled, _ := a.mfa.TOTP.Enabled(user.ID)
	recoveryCount, _ := a.mfa.Recovery.Remaining(user.ID)
	a.rnd.Render(w, r, "profile.tmpl.html", map[string]any{
		"UserID":        user.LoginID,
		"Email":         user.PrimaryEmail,
		"Enabled":       user.Enabled,
		"Success":       success,
		"Error":         errMsg,
		"TOTPEnabled":   totpEnabled,
		"RecoveryCount": recoveryCount,
	})
}

// changePassword verifies the current password and replaces the stored hash.
// The demo hashes via the public userauth helpers, as any consumer of the
// library would; userdb.SetPasswordHash stores the hash as-is.
func (a *app) changePassword(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if strings.TrimSpace(current) == "" || strings.TrimSpace(newPw) == "" {
		a.viewWithMsg(w, r, "", "Current and new passwords are required.")
		return
	}
	if newPw != confirm {
		a.viewWithMsg(w, r, "", "New passwords do not match.")
		return
	}

	user, err := a.users.GetUser(ud.UserId)
	if err != nil {
		a.viewWithMsg(w, r, "", "Could not load user.")
		return
	}
	if ok, err := userauth.VerifyPassword(current, user.HashPw); err != nil || !ok {
		a.viewWithMsg(w, r, "", "Current password is incorrect.")
		return
	}

	hashed, err := userauth.HashPassword(newPw)
	if err != nil {
		a.viewWithMsg(w, r, "", "Could not hash password.")
		return
	}
	if err := a.users.SetPasswordHash(ud.UserId, hashed); err != nil {
		a.viewWithMsg(w, r, "", "Could not update password: "+err.Error())
		return
	}
	a.viewWithMsg(w, r, "Password updated successfully.", "")
}

// changeEmail updates the user's primary email (which clears its verified flag in the store).
func (a *app) changeEmail(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		a.viewWithMsg(w, r, "", "Email address is required.")
		return
	}

	if err := a.users.SetPrimaryEmail(ud.UserId, email); err != nil {
		a.viewWithMsg(w, r, "", "Could not update email: "+err.Error())
		return
	}
	a.viewWithMsg(w, r, "Email updated successfully.", "")
}
