package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"image/png"
	"math/big"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// totpSetup generates a new TOTP secret, stores it disabled, and shows the enrolment QR code.
func (a *app) totpSetup(w http.ResponseWriter, r *http.Request) {
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
func (a *app) totpConfirm(w http.ResponseWriter, r *http.Request) {
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
	plain, err := generateRecoveryCodes(6)
	if err != nil {
		http.Error(w, "could not generate recovery codes", http.StatusInternalServerError)
		return
	}
	// the store keeps only bcrypt hashes; the plaintext is shown once below
	hashed := make([]string, 0, len(plain))
	for _, c := range plain {
		h, herr := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
		if herr != nil {
			http.Error(w, "could not hash recovery codes", http.StatusInternalServerError)
			return
		}
		hashed = append(hashed, string(h))
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
func (a *app) totpDisable(w http.ResponseWriter, r *http.Request) {
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

// generateRecoveryCodes returns count random 8-character alphanumeric codes.
// Generating (and hashing) recovery codes is application territory: the store
// only persists and verifies hashes.
func generateRecoveryCodes(count int) ([]string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const length = 8
	charsetLen := big.NewInt(int64(len(charset)))
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code := make([]byte, length)
		for j := range code {
			n, err := rand.Int(rand.Reader, charsetLen)
			if err != nil {
				return nil, err
			}
			code[j] = charset[n.Int64()]
		}
		out = append(out, string(code))
	}
	return out, nil
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
