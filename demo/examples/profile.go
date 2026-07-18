package examples

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image/png"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/hashutil"
	"github.com/go-bumbu/userauth/loginflow"
	flowmemory "github.com/go-bumbu/userauth/loginflow/memory"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// profileApp holds the dependencies shared by the profile handlers.
type profileApp struct {
	log     *slog.Logger
	users   *userdb.Store
	rnd     *web.Renderer
	sessMgr *cookieauth.Manager
	flow    *loginflow.Flow
}

// Profile demonstrates an authenticated self-service area backed by the
// userdb.Store: cookie-session password login with an optional TOTP second
// factor and recovery codes, plus password, email, and two-factor management.
func Profile(log *slog.Logger, users *userdb.Store, rnd *web.Renderer) http.Handler {
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
	policy := loginflow.PolicyFunc(func(user userauth.User, satisfied []string) (bool, []string, error) {
		if !slices.Contains(satisfied, loginflow.MethodPassword) {
			return false, []string{loginflow.MethodPassword}, nil
		}
		totpData, err := users.GetTOTP(user.Id)
		if err != nil {
			return false, nil, err
		}
		if !totpData.Enabled ||
			slices.Contains(satisfied, loginflow.MethodTOTP) ||
			slices.Contains(satisfied, loginflow.MethodRecovery) {
			return true, nil, nil
		}
		return false, []string{loginflow.MethodTOTP, loginflow.MethodRecovery}, nil
	})

	a := &profileApp{
		log:     log,
		users:   users,
		rnd:     rnd,
		sessMgr: sessMgr,
		flow: &loginflow.Flow{
			Users: users,
			Methods: []loginflow.Method{
				loginflow.PasswordMethod{Users: users},
				loginflow.TOTPMethod{TOTP: users},
				loginflow.RecoveryMethod{Codes: users},
			},
			Policy:   policy,
			Attempts: flowmemory.New(),
			Session:  sessMgr,
			Logger:   log,
		},
	}

	r := mux.NewRouter()
	r.Path("/login").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.rnd.Render(w, req, "profile_login.tmpl.html", nil)
	})
	r.Path("/login").Methods(http.MethodPost).HandlerFunc(a.loginPost)
	r.Path("/login/2fa").Methods(http.MethodPost).HandlerFunc(a.verify2FA)
	r.Path("/logout").Handler(logincookie.LogoutHandler(a.sessMgr, "/"))
	r.Path("/").Methods(http.MethodGet).Handler(a.requireAuth(http.HandlerFunc(a.view)))
	r.Path("/change-password").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.changePassword)))
	r.Path("/change-email").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.changeEmail)))
	r.Path("/totp/setup").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpSetup)))
	r.Path("/totp/confirm").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpConfirm)))
	r.Path("/totp/disable").Methods(http.MethodPost).Handler(a.requireAuth(http.HandlerFunc(a.totpDisable)))
	return r
}

// requireAuth wraps a handler so unauthenticated requests are redirected to the login page.
func (a *profileApp) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := a.sessMgr.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/profile/login", http.StatusSeeOther)
	})
}

// view renders the profile page.
func (a *profileApp) view(w http.ResponseWriter, r *http.Request) {
	a.viewWithMsg(w, r, "", "")
}

// viewWithMsg renders the profile page with an optional success or error banner.
func (a *profileApp) viewWithMsg(w http.ResponseWriter, r *http.Request, success, errMsg string) {
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
	totpData, _ := a.users.GetTOTP(user.Id)
	recoveryCount, _ := a.users.GetRecoveryCodesCount(user.Id)
	a.rnd.Render(w, r, "profile.tmpl.html", map[string]any{
		"UserID":        user.Id,
		"Email":         user.PrimaryEmail,
		"Enabled":       user.Enabled,
		"Success":       success,
		"Error":         errMsg,
		"TOTPEnabled":   totpData.Enabled,
		"RecoveryCount": recoveryCount,
	})
}

// changePassword verifies the current password and replaces the stored hash.
func (a *profileApp) changePassword(w http.ResponseWriter, r *http.Request) {
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
	ok, err := hashutil.VerifyPassword(current, user.HashPw)
	if err != nil || !ok {
		a.viewWithMsg(w, r, "", "Current password is incorrect.")
		return
	}

	hashed, err := hashutil.HashPassword(newPw)
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
func (a *profileApp) changeEmail(w http.ResponseWriter, r *http.Request) {
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

// loginPost submits the password factor to the flow, branching to the 2FA
// prompt when the policy demands a second factor and redirecting into the
// profile when the login is complete.
func (a *profileApp) loginPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	res, err := a.flow.Submit(r, w, username, loginflow.MethodPassword, password, false)
	if err != nil {
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		a.rnd.Render(w, r, "profile_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
		return
	}
	if !res.Done {
		a.rnd.Render(w, r, "profile_2fa.tmpl.html", map[string]any{"UserID": username})
		return
	}
	http.Redirect(w, r, "/profile/", http.StatusSeeOther)
}

// verify2FA submits the second factor: the code is tried as TOTP first and as
// a recovery code otherwise; the flow completes the session on success.
func (a *profileApp) verify2FA(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.FormValue("userID"))
	code := strings.TrimSpace(r.FormValue("code"))

	res, err := a.flow.Submit(r, w, userID, loginflow.MethodTOTP, code, false)
	if err != nil {
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		res, err = a.flow.Submit(r, w, userID, loginflow.MethodRecovery, code, false)
		if err != nil {
			http.Error(w, "login error", http.StatusInternalServerError)
			return
		}
	}
	if !res.Done {
		// either the code is wrong or the pending attempt expired; the 2FA
		// form lets the user retry, and an expired attempt sends them back
		// through the password step
		a.rnd.Render(w, r, "profile_2fa.tmpl.html", map[string]any{
			"UserID": userID,
			"Error":  "Invalid code, try again.",
		})
		return
	}
	http.Redirect(w, r, "/profile/", http.StatusSeeOther)
}

// totpSetup generates a new TOTP secret, stores it disabled, and shows the enrolment QR code.
func (a *profileApp) totpSetup(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "userauth-demo", AccountName: ud.UserId})
	if err != nil {
		http.Error(w, "could not generate TOTP secret", http.StatusInternalServerError)
		return
	}
	if err := a.users.SetTOTP(ud.UserId, userauth.TOTPData{Secret: key.Secret(), Enabled: false}); err != nil {
		http.Error(w, "could not store TOTP secret", http.StatusInternalServerError)
		return
	}
	qr, err := totpQRDataURI(key)
	if err != nil {
		http.Error(w, "could not render QR", http.StatusInternalServerError)
		return
	}
	a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"QRDataURI": qr,
		"Secret":    key.Secret(),
	})
}

// totpConfirm validates the first TOTP code, enables 2FA, and issues one-time recovery codes.
func (a *profileApp) totpConfirm(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	data, err := a.users.GetTOTP(ud.UserId)
	if err != nil || data.Secret == "" {
		a.viewWithMsg(w, r, "", "Please start TOTP setup again.")
		return
	}
	if !totp.Validate(code, data.Secret) {
		a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
			"Secret": data.Secret,
			"Error":  "That code didn't match. Try again.",
		})
		return
	}
	if err := a.users.SetTOTP(ud.UserId, userauth.TOTPData{Secret: data.Secret, Enabled: true}); err != nil {
		http.Error(w, "could not enable TOTP", http.StatusInternalServerError)
		return
	}
	plain, err := hashutil.GenerateRecoveryCodes(6)
	if err != nil {
		http.Error(w, "could not generate recovery codes", http.StatusInternalServerError)
		return
	}
	hashed := make([]string, 0, len(plain))
	for _, c := range plain {
		h, herr := hashutil.HashRecoveryCode(c)
		if herr != nil {
			http.Error(w, "could not hash recovery codes", http.StatusInternalServerError)
			return
		}
		hashed = append(hashed, h)
	}
	if err := a.users.SetRecoveryCodes(ud.UserId, hashed); err != nil {
		http.Error(w, "could not store recovery codes", http.StatusInternalServerError)
		return
	}
	a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"Success":       "Two-factor authentication is now enabled.",
		"RecoveryCodes": plain,
	})
}

// totpDisable turns off TOTP and clears the user's recovery codes.
func (a *profileApp) totpDisable(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	if err := a.users.SetTOTP(ud.UserId, userauth.TOTPData{Enabled: false}); err != nil {
		http.Error(w, "could not disable TOTP", http.StatusInternalServerError)
		return
	}
	if err := a.users.SetRecoveryCodes(ud.UserId, nil); err != nil {
		http.Error(w, "could not clear recovery codes", http.StatusInternalServerError)
		return
	}
	a.viewWithMsg(w, r, "Two-factor authentication disabled.", "")
}

// totpQRDataURI renders the key's otpauth URL as a base64 PNG data URI.
// template.URL keeps html/template from rejecting the data: scheme in an <img src>.
func totpQRDataURI(key *otp.Key) (template.URL, error) {
	img, err := key.Image(220, 220)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}
