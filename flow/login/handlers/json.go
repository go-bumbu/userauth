// Package handlers provides ready-made HTTP transports on top of
// login.Flow for common login flows, with JSON request/response bodies
// suited to single-page applications.
//
// The transport stays deliberately dumb: it parses payloads, calls the flow,
// and encodes results. Every security decision — factor ordering, uniform
// credential failures, enumeration resistance, session creation — lives in
// the flow engine. All credential-shaped failures produce the identical
// 401 response.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/flow/login"
)

// JSON exposes a login.Flow as JSON endpoints. Use one of the preset
// constructors (NewPasswordTOTP, NewEmailCode) for the common flows, or wrap
// a custom Flow directly.
//
// Typical SPA wiring:
//
//	j := handlers.NewPasswordTOTP(handlers.PasswordTOTPCfg{ ... })
//	mux.Handle("POST /api/login", j.LoginHandler())
//	mux.Handle("POST /api/login/verify", j.VerifyHandler())
type JSON struct {
	Flow   *login.Flow
	Logger *slog.Logger // optional; defaults to slog.Default()
}

// LoginPayload is the request body for LoginHandler.
type LoginPayload struct {
	User         string `json:"username"`
	Password     string `json:"password"`
	SessionRenew bool   `json:"sessionRenew"`
}

// VerifyPayload is the request body for VerifyHandler.
type VerifyPayload struct {
	User   string `json:"username"`
	Method string `json:"method"` // e.g. "totp", "recovery", "email"
	Code   string `json:"code"`
	// SessionRenew only matters when this verification is the first factor
	// of the flow (e.g. passwordless email login); otherwise the value
	// captured at the first factor wins.
	SessionRenew bool `json:"sessionRenew"`
}

// RequestCodePayload is the request body for RequestCodeHandler.
type RequestCodePayload struct {
	User   string `json:"username"`
	Method string `json:"method,omitempty"` // defaults to "email"
}

// Response is the success body of LoginHandler and VerifyHandler.
type Response struct {
	// Done reports that the login is complete and the session was created.
	Done bool `json:"done"`
	// Next lists the method IDs the user may attempt now; set when the
	// submitted factor was accepted but the policy requires more.
	Next []string `json:"next,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// LoginHandler returns the POST endpoint for the password step.
//
// Responses:
//   - 200 {"done":true} — login complete, session created
//   - 200 {"done":false,"next":["totp",...]} — password accepted, second factor required
//   - 401 {"error":"unauthorized"} — identical for unknown user, disabled user and wrong password
//   - 400 / 405 / 500 for malformed requests, wrong method, internal failures
func (h *JSON) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p LoginPayload
		if !h.decode(w, r, &p) {
			return
		}
		if p.User == "" || p.Password == "" {
			h.writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}
		if !h.methodAvailable(login.MethodPassword) {
			h.writeError(w, http.StatusBadRequest, "password login not available")
			return
		}
		res, err := h.Flow.Submit(r, w, p.User, login.MethodPassword, p.Password, p.SessionRenew)
		h.respond(w, res, err)
	})
}

// VerifyHandler returns the POST endpoint that submits a one-time code
// factor: a TOTP or recovery code completing a password login, or an email
// code as the first factor of a passwordless login.
//
// Responses mirror LoginHandler; a code for a factor the policy is not
// currently offering (e.g. TOTP before the password step, or an expired
// attempt) yields the same 401 as a wrong code.
func (h *JSON) VerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p VerifyPayload
		if !h.decode(w, r, &p) {
			return
		}
		if p.User == "" || p.Method == "" || p.Code == "" {
			h.writeError(w, http.StatusBadRequest, "username, method and code are required")
			return
		}
		if !h.methodAvailable(p.Method) {
			h.writeError(w, http.StatusBadRequest, "unknown method")
			return
		}
		res, err := h.Flow.Submit(r, w, p.User, p.Method, p.Code, p.SessionRenew)
		h.respond(w, res, err)
	})
}

// RequestCodeHandler returns the POST endpoint that requests delivery of a
// one-time code (method defaults to "email").
//
// It always responds 202 {} regardless of whether the user exists, is
// enabled, or the code could be delivered — the flow engine issues codes only
// to known enabled users and logs failures server-side, so the endpoint
// cannot be used to probe which accounts exist.
func (h *JSON) RequestCodeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p RequestCodePayload
		if !h.decode(w, r, &p) {
			return
		}
		if p.User == "" {
			h.writeError(w, http.StatusBadRequest, "username is required")
			return
		}
		method := p.Method
		if method == "" {
			method = login.MethodEmail
		}
		if !h.initiatorAvailable(method) {
			h.writeError(w, http.StatusBadRequest, "method does not support code delivery")
			return
		}
		if err := h.Flow.Initiate(r, p.User, method); err != nil {
			h.logger().Error("json login: initiate failed", "method", method, "error", err)
			h.writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		h.writeJSON(w, http.StatusAccepted, struct{}{})
	})
}

func (h *JSON) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// decode enforces POST and parses the JSON body; it writes the error
// response itself and returns false when the request is unusable.
func (h *JSON) decode(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "wrong method")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// methodAvailable reports whether the flow has the method registered, so a
// client picking an unknown method gets a 400 instead of a misleading 500.
func (h *JSON) methodAvailable(id string) bool {
	for _, m := range h.Flow.Methods {
		if m.ID() == id {
			return true
		}
	}
	return false
}

// initiatorAvailable reports whether the method is registered and can issue
// codes.
func (h *JSON) initiatorAvailable(id string) bool {
	for _, m := range h.Flow.Methods {
		if m.ID() == id {
			_, ok := m.(login.Initiator)
			return ok
		}
	}
	return false
}

// respond translates a Submit result: internal errors become a generic 500,
// any credential-shaped failure becomes one uniform 401, and accepted
// factors report done/next.
func (h *JSON) respond(w http.ResponseWriter, res login.Result, err error) {
	if err != nil {
		h.logger().Error("json login: flow error", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !res.OK {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	h.writeJSON(w, http.StatusOK, Response{Done: res.Done, Next: res.Next})
}

func (h *JSON) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger().Debug("json login: failed to encode response", "error", err)
	}
}

func (h *JSON) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, errorResponse{Error: msg})
}
