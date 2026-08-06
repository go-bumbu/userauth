// Package handlers provides ready-made JSON endpoints on top of the pat
// flow: create (returns the plaintext token exactly once), list (metadata
// only — never the secret or its hash), and delete. All endpoints require
// an authenticated session; the flow's UserID func decides what that means.
package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"time"

	flowpat "github.com/go-bumbu/userauth/flow/pat"
	patsvc "github.com/go-bumbu/userauth/service/pat"
)

// JSON exposes a pat.Flow as JSON endpoints.
type JSON struct {
	Flow   *flowpat.Flow
	Logger *slog.Logger
}

// CreatePayload is the request body for CreateHandler.
type CreatePayload struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // RFC3339; absent = never
}

// TokenMeta is one token's metadata; it never carries secret material.
type TokenMeta struct {
	TokenID    string     `json:"token_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateResponse is the body of a successful create. Token is the full
// plaintext token; this response is the only place it ever appears.
type CreateResponse struct {
	Token string `json:"token"`
	TokenMeta
}

// ListResponse is the body of a successful list.
type ListResponse struct {
	Tokens []TokenMeta `json:"tokens"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func toMeta(rec patsvc.TokenRecord) TokenMeta {
	return TokenMeta{
		TokenID:    rec.TokenID,
		Name:       rec.Name,
		Scopes:     rec.Scopes,
		ExpiresAt:  rec.ExpiresAt,
		LastUsedAt: rec.LastUsedAt,
		CreatedAt:  rec.CreatedAt,
	}
}

// CreateHandler returns the POST endpoint that mints a token.
//
// Responses:
//   - 201 CreateResponse — the "token" field appears here and never again
//   - 400 for invalid name/expiry, over-limit, malformed body
//   - 401 when the request has no authenticated user
//   - 405 for non-POST requests
//   - 500 for store failures
func (h *JSON) CreateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var p CreatePayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		plaintext, rec, err := h.Flow.Create(r, p.Name, p.Scopes, p.ExpiresAt)
		if err != nil {
			h.writeFlowError(w, err)
			return
		}
		h.writeJSON(w, http.StatusCreated, CreateResponse{Token: plaintext, TokenMeta: toMeta(rec)})
	})
}

// ListHandler returns the GET endpoint listing the user's tokens (metadata only).
//
// Responses:
//   - 200 ListResponse with token metadata
//   - 401 when the request has no authenticated user
//   - 405 for non-GET requests
//   - 500 for store failures
func (h *JSON) ListHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		recs, err := h.Flow.List(r)
		if err != nil {
			h.writeFlowError(w, err)
			return
		}
		out := ListResponse{Tokens: make([]TokenMeta, 0, len(recs))}
		for _, rec := range recs {
			out.Tokens = append(out.Tokens, toMeta(rec))
		}
		h.writeJSON(w, http.StatusOK, out)
	})
}

// DeleteHandler returns the DELETE endpoint revoking one token. The token ID
// is the last path segment, so it works with any router (net/http patterns,
// gorilla/mux, plain StripPrefix mounts).
//
// Responses:
//   - 204 on successful revocation
//   - 400 for missing/invalid token ID
//   - 401 when the request has no authenticated user
//   - 404 when token not found or not owned by the user
//   - 405 for non-DELETE requests
//   - 500 for store failures
func (h *JSON) DeleteHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		tokenID := path.Base(r.URL.Path)
		if tokenID == "" || tokenID == "/" || tokenID == "." {
			h.writeError(w, http.StatusBadRequest, "token id is required")
			return
		}
		if err := h.Flow.Revoke(r, tokenID); err != nil {
			h.writeFlowError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// writeFlowError maps flow/service errors to HTTP responses.
func (h *JSON) writeFlowError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, flowpat.ErrNoIdentity):
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, patsvc.ErrInvalidName),
		errors.Is(err, patsvc.ErrInvalidExpiry),
		errors.Is(err, patsvc.ErrTooManyTokens):
		h.writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, patsvc.ErrTokenNotFound):
		h.writeError(w, http.StatusNotFound, "token not found")
	default:
		h.logger().Error("pat handler: internal error", "err", err)
		h.writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *JSON) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger().Error("pat handler: encode response", "err", err)
	}
}

func (h *JSON) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, errorResponse{Error: msg})
}

func (h *JSON) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}
