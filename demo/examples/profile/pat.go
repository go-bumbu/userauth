package profile

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	patsvc "github.com/go-bumbu/userauth/service/pat"
)

// patView renders the PAT management page, optionally showing a
// just-created token once (postMint) or a banner message.
func (a *app) patView(w http.ResponseWriter, r *http.Request) {
	a.patViewWithMsg(w, r, "", "", "")
}

func (a *app) patViewWithMsg(w http.ResponseWriter, r *http.Request, newToken, success, errMsg string) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	recs, err := a.pats.List(ud.UserId)
	if err != nil {
		http.Error(w, "could not list tokens", http.StatusInternalServerError)
		return
	}
	type row struct {
		TokenID, Name, Scopes, Expires, LastUsed, Created string
	}
	rows := make([]row, 0, len(recs))
	for _, rec := range recs {
		x := row{
			TokenID: rec.TokenID,
			Name:    rec.Name,
			Scopes:  strings.Join(rec.Scopes, ", "),
			Created: rec.CreatedAt.Format("2006-01-02 15:04"),
			Expires: "never",
		}
		if rec.ExpiresAt != nil {
			x.Expires = rec.ExpiresAt.Format("2006-01-02 15:04")
		}
		if rec.LastUsedAt != nil {
			x.LastUsed = rec.LastUsedAt.Format("2006-01-02 15:04")
		}
		rows = append(rows, x)
	}
	a.rnd.Render(w, r, "profile_pat.tmpl.html", map[string]any{
		"Tokens":   rows,
		"NewToken": newToken,
		"Success":  success,
		"Error":    errMsg,
	})
}

// patCreate mints a token from the form (name, optional expiry days, optional
// comma-separated scopes) and shows it exactly once.
func (a *app) patCreate(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	name := r.FormValue("name")
	var scopes []string
	for _, s := range strings.Split(r.FormValue("scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	var expiresAt *time.Time
	if d := strings.TrimSpace(r.FormValue("expiry_days")); d != "" {
		days, err := strconv.Atoi(d)
		if err != nil || days <= 0 {
			a.patViewWithMsg(w, r, "", "", "Expiry must be a positive number of days.")
			return
		}
		t := time.Now().AddDate(0, 0, days)
		expiresAt = &t
	}
	plaintext, _, err := a.pats.Mint(ud.UserId, name, scopes, expiresAt, patsvc.HashOnly)
	if err != nil {
		a.patViewWithMsg(w, r, "", "", "Could not create token: "+err.Error())
		return
	}
	a.patViewWithMsg(w, r, plaintext, "Token created — copy it now, it will not be shown again.", "")
}

// patRevoke deletes the token named by the form's token_id.
func (a *app) patRevoke(w http.ResponseWriter, r *http.Request) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	if err := a.pats.Revoke(ud.UserId, r.FormValue("token_id")); err != nil {
		a.patViewWithMsg(w, r, "", "", "Could not revoke token: "+err.Error())
		return
	}
	a.patViewWithMsg(w, r, "", "Token revoked.", "")
}
