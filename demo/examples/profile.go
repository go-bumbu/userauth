package examples

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"image/png"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	logincookie "github.com/go-bumbu/userauth/handlers/login"
	"github.com/go-bumbu/userauth/hashutil"
	pendingmemory "github.com/go-bumbu/userauth/pendinglogin/memory"
	"github.com/go-bumbu/userauth/userstore/dbusers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type profileApp struct {
	log     *slog.Logger
	users   *dbusers.DbManager
	rnd     *web.Renderer
	sessMgr *cookieauth.Manager
	login   userauth.LoginHandler
	pending *pendingmemory.Store
}

func Profile(log *slog.Logger, users *dbusers.DbManager, rnd *web.Renderer) http.Handler {
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
	a := &profileApp{
		log:     log,
		users:   users,
		rnd:     rnd,
		sessMgr: sessMgr,
		login: userauth.LoginHandler{
			UserStore:     users,
			SecondFactors: users,
			TOTP:          users,
			RecoveryCode:  users,
		},
		pending: pendingmemory.New(),
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

func (a *profileApp) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := a.sessMgr.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/profile/login", http.StatusSeeOther)
	})
}

func (a *profileApp) view(w http.ResponseWriter, r *http.Request) {
	a.viewWithMsg(w, r, "", "")
}

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

func (a *profileApp) loginPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	result, err := a.login.CanLogin(username, password)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) || errors.Is(err, userauth.ErrUserDisabled) {
			a.rnd.Render(w, r, "profile_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
			return
		}
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}

	if result.Authenticated {
		if err := a.sessMgr.LoginUser(r, w, result.UserID, false); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/profile/", http.StatusSeeOther)
		return
	}

	if result.Requires2FA {
		if err := a.pending.SetPendingLogin(r, w, logincookie.PendingLogin{
			UserID:    result.UserID,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		a.rnd.Render(w, r, "profile_2fa.tmpl.html", map[string]any{"UserID": result.UserID})
		return
	}

	a.rnd.Render(w, r, "profile_login.tmpl.html", map[string]any{"Error": "Invalid credentials."})
}

func (a *profileApp) verify2FA(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.FormValue("userID"))
	code := strings.TrimSpace(r.FormValue("code"))

	if _, err := a.pending.GetPendingLogin(r, userID); err != nil {
		a.rnd.Render(w, r, "profile_login.tmpl.html", map[string]any{
			"Error": "Login session expired, please log in again.",
		})
		return
	}

	res, _ := a.login.VerifyTOTP(userID, code)
	if !res.Authenticated {
		res, _ = a.login.VerifyRecoveryCode(userID, code)
	}
	if !res.Authenticated {
		a.rnd.Render(w, r, "profile_2fa.tmpl.html", map[string]any{
			"UserID": userID,
			"Error":  "Invalid code, try again.",
		})
		return
	}

	_ = a.pending.ClearPendingLogin(r, w, userID)
	if err := a.sessMgr.LoginUser(r, w, userID, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile/", http.StatusSeeOther)
}

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
