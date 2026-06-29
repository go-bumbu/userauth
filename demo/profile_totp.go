package main

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image/png"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/handlers/auth/cookieauth"
	"github.com/go-bumbu/userauth/hashutil"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func profileTOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
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
	if err := dbUserMgr.SetTOTP(ud.UserId, userauth.TOTPData{Secret: key.Secret(), Enabled: false}); err != nil {
		http.Error(w, "could not store TOTP secret", http.StatusInternalServerError)
		return
	}
	qr, err := totpQRDataURI(key)
	if err != nil {
		http.Error(w, "could not render QR", http.StatusInternalServerError)
		return
	}
	renderTmpl(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"QRDataURI": qr,
		"Secret":    key.Secret(),
	})
}

func profileTOTPConfirmHandler(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	data, err := dbUserMgr.GetTOTP(ud.UserId)
	if err != nil || data.Secret == "" {
		profileViewWithMsg(w, r, "", "Please start TOTP setup again.")
		return
	}
	if !totp.Validate(code, data.Secret) {
		renderTmpl(w, r, "profile_totp_setup.tmpl.html", map[string]any{
			"Secret": data.Secret,
			"Error":  "That code didn't match. Try again.",
		})
		return
	}
	if err := dbUserMgr.SetTOTP(ud.UserId, userauth.TOTPData{Secret: data.Secret, Enabled: true}); err != nil {
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
	if err := dbUserMgr.SetRecoveryCodes(ud.UserId, hashed); err != nil {
		http.Error(w, "could not store recovery codes", http.StatusInternalServerError)
		return
	}
	renderTmpl(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"Success":       "Two-factor authentication is now enabled.",
		"RecoveryCodes": plain,
	})
}

func profileTOTPDisableHandler(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	if err := dbUserMgr.SetTOTP(ud.UserId, userauth.TOTPData{Enabled: false}); err != nil {
		http.Error(w, "could not disable TOTP", http.StatusInternalServerError)
		return
	}
	if err := dbUserMgr.SetRecoveryCodes(ud.UserId, nil); err != nil {
		http.Error(w, "could not clear recovery codes", http.StatusInternalServerError)
		return
	}
	profileViewWithMsg(w, r, "Two-factor authentication disabled.", "")
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
