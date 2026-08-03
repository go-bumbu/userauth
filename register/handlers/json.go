// Package handlers provides a ready-made HTTP transport on top of
// register.Flow, with JSON request/response bodies suited to single-page
// applications.
//
// The transport stays deliberately dumb: it parses payloads, calls the flow,
// and encodes results. Every registration decision — check ordering, uniform
// rejections, account creation — lives in the flow engine.
//
// Unlike the login transport, registration deliberately reveals whether a
// username is taken (409): see the register package documentation.
package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/register"
)

// JSON exposes a register.Flow as JSON endpoints. Use the preset constructor
// (New) for the common flows, or wrap a custom Flow directly.
//
// Typical SPA wiring:
//
//	j := handlers.New(handlers.Cfg{ ... })
//	mux.Handle("POST /api/register", j.RegisterHandler())
//	mux.Handle("POST /api/register/verify", j.VerifyHandler())
//	mux.Handle("POST /api/register/request-code", j.RequestCodeHandler())
type JSON struct {
	Flow   *register.Flow
	Logger *slog.Logger // optional; defaults to slog.Default()
}

// RegisterPayload is the request body for RegisterHandler.
type RegisterPayload struct {
	User       string `json:"username"`
	Password   string `json:"password"`
	Email      string `json:"email,omitempty"`      // required with email verification unless the username is the email
	InviteCode string `json:"inviteCode,omitempty"` // required with invite gating
}

// VerifyPayload is the request body for VerifyHandler.
type VerifyPayload struct {
	User  string `json:"username"`
	Check string `json:"check"` // e.g. "email"
	Code  string `json:"code"`
}

// RequestCodePayload is the request body for RequestCodeHandler.
type RequestCodePayload struct {
	User  string `json:"username"`
	Check string `json:"check,omitempty"` // defaults to "email"
}

// Response is the success body of RegisterHandler and VerifyHandler. It has
// the same shape as the login transport's response, so SPAs can share client
// code.
type Response struct {
	// Done reports that the registration is complete and the account was
	// created.
	Done bool `json:"done"`
	// Next lists the check IDs still pending; set when the submission was
	// accepted but more checks are required.
	Next []string `json:"next,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// RegisterHandler returns the POST endpoint that starts a registration.
//
// Responses:
//   - 200 {"done":true} — registration complete, account created
//   - 200 {"done":false,"next":["email"]} — accepted, verification pending
//   - 409 {"error":"username taken"} — the login ID is in use
//   - 400 {"error":"..."} — rejected input (password policy, login format, missing fields)
//   - 401 {"error":"unauthorized"} — uniform for credential-shaped rejections (e.g. bad invite)
//   - 405 / 500 for wrong method and internal failures
func (h *JSON) RegisterHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p RegisterPayload
		if !h.decode(w, r, &p) {
			return
		}
		if p.User == "" || p.Password == "" {
			h.writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}
		res, err := h.Flow.Start(r, w, register.StartInput{
			LoginID:    p.User,
			Password:   p.Password,
			Email:      p.Email,
			InviteCode: p.InviteCode,
		})
		h.respond(w, res, err)
	})
}

// VerifyHandler returns the POST endpoint that submits a round-trip check,
// e.g. the emailed verification code.
//
// Responses mirror RegisterHandler; a wrong or expired code, a missing
// pending registration and a replayed check all yield the same 401.
func (h *JSON) VerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p VerifyPayload
		if !h.decode(w, r, &p) {
			return
		}
		if p.User == "" || p.Check == "" || p.Code == "" {
			h.writeError(w, http.StatusBadRequest, "username, check and code are required")
			return
		}
		if !h.checkAvailable(p.Check) {
			h.writeError(w, http.StatusBadRequest, "unknown check")
			return
		}
		res, err := h.Flow.VerifyCheck(r, w, p.User, p.Check, p.Code)
		h.respond(w, res, err)
	})
}

// RequestCodeHandler returns the POST endpoint that re-requests delivery of
// a verification code (check defaults to "email").
//
// It always responds 202 {} regardless of whether a registration is pending
// — the flow engine only issues codes for usable pending registrations and
// logs failures server-side, so the endpoint cannot be used to probe which
// registrations are in progress.
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
		check := p.Check
		if check == "" {
			check = register.CheckEmail
		}
		if !h.initiatorAvailable(check) {
			h.writeError(w, http.StatusBadRequest, "check does not support code delivery")
			return
		}
		if err := h.Flow.Initiate(r, p.User, check); err != nil {
			h.logger().Error("json register: initiate failed", "check", check, "error", err)
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

// checkAvailable reports whether the flow has the check registered, so a
// client picking an unknown check gets a 400 instead of a misleading 500.
func (h *JSON) checkAvailable(id string) bool {
	for _, c := range h.Flow.Checks {
		if c.ID() == id {
			return true
		}
	}
	return false
}

// initiatorAvailable reports whether the check is registered and can issue
// codes.
func (h *JSON) initiatorAvailable(id string) bool {
	for _, c := range h.Flow.Checks {
		if c.ID() == id {
			_, ok := c.(register.Initiator)
			return ok
		}
	}
	return false
}

// respond translates a flow result: ErrUserExists becomes 409, validation
// errors become 400 with the message, other errors become a generic 500,
// any credential-shaped rejection becomes one uniform 401, and accepted
// submissions report done/next.
func (h *JSON) respond(w http.ResponseWriter, res register.Result, err error) {
	if err != nil {
		if errors.Is(err, register.ErrUserExists) {
			h.writeError(w, http.StatusConflict, "username taken")
			return
		}
		var vErr *register.ValidationError
		if errors.As(err, &vErr) {
			h.writeError(w, http.StatusBadRequest, vErr.Msg)
			return
		}
		h.logger().Error("json register: flow error", "error", err)
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
		h.logger().Debug("json register: failed to encode response", "error", err)
	}
}

func (h *JSON) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, errorResponse{Error: msg})
}
