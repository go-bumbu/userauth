// Package tokenauth authenticates API requests carrying a personal access
// token, as an auth handler for the chain authenticator. Tokens are read
// from the Authorization header (Bearer scheme by default) or an optional
// custom header; verification is delegated to a Verifier (service/pat
// provides one via Service.ChainVerifier).
//
// Enforce semantics differ deliberately from headerauth: Enforce only stops
// chain evaluation when a token was PRESENTED and is invalid. A request
// with no token always falls through to later chain handlers, so tokenauth
// can sit in front of cookie or basic auth without locking browsers out.
package tokenauth

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth/auth/chain"
)

const authName = "tokenauth"

const defaultBearerScheme = "Bearer"

// RequestData is the identity a verified token asserts for the request.
// Scopes are opaque strings; what a scope permits is defined entirely by
// the consuming application.
type RequestData struct {
	UserID  string
	LoginID string
	TokenID string
	Name    string
	Scopes  []string
}

// Verifier turns a presented token into an identity. ok=false is a
// credential failure (uniform, no reason); err is an internal failure.
type Verifier interface {
	Verify(token string) (data RequestData, ok bool, err error)
}

// Cfg configures the token auth handler.
type Cfg struct {
	// Verifier validates presented tokens. Required.
	Verifier Verifier
	// CustomHeader is an additional plain header to read the token from
	// (e.g. "X-Api-Token") for clients that cannot set Authorization.
	// Empty disables it. Authorization always wins when both are present.
	CustomHeader string
	// BearerScheme overrides the Authorization scheme keyword. Empty means
	// "Bearer". Matching is case-insensitive.
	BearerScheme string
	// Enforce stops chain evaluation when a token is presented but invalid,
	// making this handler the final authority for token-bearing requests.
	// Requests without any token always fall through.
	Enforce bool
	Logger  *slog.Logger
}

// Handler authenticates requests from personal access tokens. It implements
// chain.AuthHandler.
type Handler struct {
	verifier     Verifier
	customHeader string
	scheme       string
	enforce      bool
	logger       *slog.Logger
}

// New creates a token auth handler from the config.
func New(cfg Cfg) (*Handler, error) {
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("tokenauth: Verifier is required")
	}
	if cfg.BearerScheme == "" {
		cfg.BearerScheme = defaultBearerScheme
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Handler{
		verifier:     cfg.Verifier,
		customHeader: cfg.CustomHeader,
		scheme:       cfg.BearerScheme,
		enforce:      cfg.Enforce,
		logger:       cfg.Logger.With("auth-handler", authName),
	}, nil
}

// Name implements chain.AuthHandler.
func (h *Handler) Name() string { return authName }

// Verify chain.AuthHandler at compile time.
var _ chain.AuthHandler = (*Handler)(nil)

// HandleAuth implements chain.AuthHandler. On success it stores the token
// identity in the request context; read it with CtxGetRequestData.
func (h *Handler) HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool) {
	token, present := h.extractToken(r)
	if !present {
		return false, false
	}
	data, ok, err := h.verifier.Verify(token)
	if err != nil {
		h.logger.Error("token auth: verifier failure", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return false, true
	}
	if !ok {
		h.logger.Debug("token auth: invalid token presented")
		return false, h.enforce
	}
	CtxSetRequestData(r, data)
	h.logger.Debug("token auth: authenticated", "user", data.UserID, "tokenID", data.TokenID)
	return true, false
}

// extractToken finds a presented token: Authorization first (only when the
// scheme matches — a Basic header is not a token and falls through), then
// the custom header when configured.
func (h *Handler) extractToken(r *http.Request) (string, bool) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, rest, found := strings.Cut(auth, " ")
		if found && strings.EqualFold(scheme, h.scheme) {
			rest = strings.TrimSpace(rest)
			if rest != "" {
				return rest, true
			}
		}
		// wrong scheme or empty credentials: not a token for us
	}
	if h.customHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(h.customHeader)); v != "" {
			return v, true
		}
	}
	return "", false
}

// Middleware returns a token-only middleware that allows access when the
// request carries a valid token.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := h.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
