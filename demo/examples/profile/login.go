package profile

import (
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/flow/login"
)

// loginPost submits the password factor to the flow, branching to the 2FA
// prompt when the policy demands a second factor and redirecting into the
// profile when the login is complete.
func (a *app) loginPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	res, err := a.flow.Submit(r, w, username, login.MethodPassword, password, false)
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
func (a *app) verify2FA(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.FormValue("userID"))
	code := strings.TrimSpace(r.FormValue("code"))

	res, err := a.flow.Submit(r, w, userID, login.MethodTOTP, code, false)
	if err != nil {
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}
	if !res.OK {
		res, err = a.flow.Submit(r, w, userID, login.MethodRecovery, code, false)
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
