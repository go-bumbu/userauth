package login

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-bumbu/userauth"
)

// CodeIssuer generates and persists a one-time login code for a user.
// *userauth.VerificationCodeService satisfies this.
type CodeIssuer interface {
	Generate(userID string) (code string, expiresAt time.Time, err error)
}

// EmailCodeLogin provides the two HTTP steps of passwordless email-code login:
// RequestHandler issues and delivers a one-time code, VerifyHandler checks it
// and creates a session.
//
// The handlers own the security decisions: a code is only issued to a known,
// enabled user, the user is re-checked at verification time, and the response
// to an unknown or disabled email is identical to the success response so the
// endpoint cannot be used to probe which accounts exist. The caller owns the
// presentation through the optional hooks; every hook has a safe default.
//
// Note: Deliver is called synchronously, so a slow deliverer (e.g. SMTP) can
// still reveal account existence through response timing. Deliverers that
// queue the message and return immediately avoid this.
type EmailCodeLogin struct {
	Users   userauth.UserGetter    // codes are only issued to known, enabled users
	Codes   CodeIssuer             // generates and stores one-time codes
	Deliver userauth.Deliverer     // sends the code to the user (email, SMS, …)
	Auth    *userauth.LoginHandler // verifies codes; its EmailCode field must be wired
	Session UserLogin              // creates the session after successful verification

	// VerifyURL is the page with the code-entry form. The default CodeSent
	// response redirects there with ?email=<email> appended.
	VerifyURL string
	// SuccessRedirect is where VerifyHandler redirects after login; when empty
	// it responds 200 with an empty body.
	SuccessRedirect string

	// CodeSent renders the response after a code request. It is also called
	// for unknown or disabled emails — keep the rendering identical in both
	// cases to preserve the anti-enumeration guarantee.
	// Default: 303 redirect to VerifyURL?email=<email>.
	CodeSent func(w http.ResponseWriter, r *http.Request, email string)
	// VerifyFail renders the response for an invalid or expired code.
	// Default: 401 Unauthorized.
	VerifyFail func(w http.ResponseWriter, r *http.Request, email string)
	// OnSuccess is called after the session is created, before the success
	// response is written. Intended for audit logging or cleanup.
	OnSuccess func(r *http.Request, email string)

	Logger *slog.Logger // optional; defaults to slog.Default()
}

func (h *EmailCodeLogin) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// RequestHandler returns an HTTP handler that accepts a form POST with an
// "email" field and issues a one-time login code for that address. The code is
// only generated and delivered when the email belongs to a known, enabled
// user; in every other case (unknown email, disabled user, generation or
// delivery failure) the failure is logged and the response is the same
// CodeSent rendering, so the endpoint never discloses whether an account
// exists.
func (h *EmailCodeLogin) RequestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unable to parse form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		if email == "" {
			http.Error(w, "email is required", http.StatusBadRequest)
			return
		}

		if user, err := h.Users.GetUser(email); err == nil && user.Enabled {
			code, expiresAt, err := h.Codes.Generate(email)
			if err != nil {
				h.logger().Error("email code: generate failed", "email", email, "error", err)
			} else if err := h.Deliver.Deliver(r.Context(), email, code, expiresAt); err != nil {
				h.logger().Error("email code: delivery failed", "email", email, "error", err)
			}
		} else {
			h.logger().Debug("email code: not issuing code", "email", email)
		}

		h.codeSent(w, r, email)
	})
}

func (h *EmailCodeLogin) codeSent(w http.ResponseWriter, r *http.Request, email string) {
	if h.CodeSent != nil {
		h.CodeSent(w, r, email)
		return
	}
	http.Redirect(w, r, h.VerifyURL+"?email="+url.QueryEscape(email), http.StatusSeeOther)
}

// VerifyHandler returns an HTTP handler that accepts a form POST with "email",
// "code" and optional "session_renew" fields, verifies (and consumes) the
// one-time code, and creates a session on success. The user must still be
// known and enabled at verification time. All credential failures — bad code,
// expired code, unknown or disabled user — produce the same VerifyFail
// rendering.
func (h *EmailCodeLogin) VerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unable to parse form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		code := strings.TrimSpace(r.FormValue("code"))
		sessRen := r.FormValue("session_renew") == "on"
		if email == "" || code == "" {
			http.Error(w, "email and code are required", http.StatusBadRequest)
			return
		}

		// The account could have been disabled in the window between code
		// request and verification; re-check before accepting the code.
		if user, err := h.Users.GetUser(email); err != nil || !user.Enabled {
			h.logger().Debug("email code: user unknown or disabled at verify", "email", email)
			h.verifyFail(w, r, email)
			return
		}

		result, err := h.Auth.VerifyEmailCode(email, code)
		if err != nil {
			h.logger().Error("email code: verify error", "email", email, "error", err)
			h.verifyFail(w, r, email)
			return
		}
		if !result.Authenticated {
			h.logger().Debug("email code: invalid or expired code", "email", email)
			h.verifyFail(w, r, email)
			return
		}

		userID := result.UserID
		if userID == "" {
			userID = email
		}
		if err := h.Session.LoginUser(r, w, userID, sessRen); err != nil {
			h.logger().Error("email code: failed to create session", "email", email, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if h.OnSuccess != nil {
			h.OnSuccess(r, email)
		}
		if h.SuccessRedirect != "" {
			http.Redirect(w, r, h.SuccessRedirect, http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (h *EmailCodeLogin) verifyFail(w http.ResponseWriter, r *http.Request, email string) {
	if h.VerifyFail != nil {
		h.VerifyFail(w, r, email)
		return
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
