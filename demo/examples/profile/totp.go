package profile

import (
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	totpsvc "github.com/go-bumbu/userauth/service/totp"
)

// totpSetup starts enrolment: the service generates and stores a secret
// (disabled until confirmed) and hands back the QR-ready otpauth URI.
func (a *app) totpSetup(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	// the authenticator app shows the account name; use the human-readable
	// login ID, not the canonical UUID the session carries
	user, err := a.users.GetUser(ud.UserId)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}
	enrolment, err := a.mfa.TOTP.Enroll(ud.UserId, user.LoginID)
	if err != nil {
		http.Error(w, "could not start TOTP enrolment", http.StatusInternalServerError)
		return
	}
	a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"ShowQR": true,
		"Secret": enrolment.Secret,
	})
}

// totpQR serves the enrolment QR code for the user's pending secret as a PNG.
// Serving the image from its own endpoint keeps the HTML template free of raw
// data URIs (which would need an unsafe template.URL conversion).
func (a *app) totpQR(w http.ResponseWriter, r *http.Request) {
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
	// only a pending enrolment has a QR to show: once confirmed, the secret is
	// not handed out again
	enrolment, pending, err := a.mfa.TOTP.Pending(ud.UserId, user.LoginID)
	if err != nil {
		http.Error(w, "could not load enrolment", http.StatusInternalServerError)
		return
	}
	if !pending {
		http.NotFound(w, r)
		return
	}
	png, err := totpsvc.QRPNG(enrolment.URI, 220)
	if err != nil {
		http.Error(w, "could not render QR", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(png); err != nil {
		a.log.Error("profile: writing TOTP QR png", "error", err)
	}
}

// totpConfirm validates the first code, which enables the factor, then issues
// the one-time recovery codes.
func (a *app) totpConfirm(w http.ResponseWriter, r *http.Request) {
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
	code := strings.TrimSpace(r.FormValue("code"))

	ok, err := a.mfa.TOTP.Confirm(ud.UserId, code)
	if err != nil {
		// no pending enrolment (or the store failed): send the user back to the
		// start rather than showing a form with nothing behind it
		a.viewWithMsg(w, r, "", "Please start TOTP setup again.")
		return
	}
	if !ok {
		enrolment, pending, perr := a.mfa.TOTP.Pending(ud.UserId, user.LoginID)
		if perr != nil || !pending {
			a.viewWithMsg(w, r, "", "Please start TOTP setup again.")
			return
		}
		a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
			"Secret": enrolment.Secret,
			"Error":  "That code didn't match. Try again.",
		})
		return
	}

	// the service keeps only bcrypt hashes; the plaintext is shown once below
	codes, err := a.mfa.Recovery.Issue(ud.UserId)
	if err != nil {
		http.Error(w, "could not generate recovery codes", http.StatusInternalServerError)
		return
	}
	a.rnd.Render(w, r, "profile_totp_setup.tmpl.html", map[string]any{
		"Success":       "Two-factor authentication is now enabled.",
		"RecoveryCodes": codes,
	})
}

// totpDisable turns off TOTP and clears the user's recovery codes: the codes
// exist to get past the authenticator, so they must not outlive it.
func (a *app) totpDisable(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	if err := a.mfa.TOTP.Disable(ud.UserId); err != nil {
		http.Error(w, "could not disable TOTP", http.StatusInternalServerError)
		return
	}
	if err := a.mfa.Recovery.Clear(ud.UserId); err != nil {
		http.Error(w, "could not clear recovery codes", http.StatusInternalServerError)
		return
	}
	a.viewWithMsg(w, r, "Two-factor authentication disabled.", "")
}
