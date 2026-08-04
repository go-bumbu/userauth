// Package headerauth authenticates requests from identity headers injected by
// a trusted reverse proxy (e.g. Authelia/Authentik behind Traefik or nginx
// forward-auth). The proxy owns the trust decision: the deployment must
// guarantee that clients cannot reach the service without passing through the
// proxy, and that the proxy strips inbound identity headers on every request.
// TrustedProxies adds a defense-in-depth check on top of that guarantee.
//
// Header names and the group separator are configuration: different proxies
// use different conventions (Authelia: Remote-User/Remote-Groups,
// oauth2-proxy: X-Forwarded-User/X-Forwarded-Groups, ...). Groups are opaque
// strings transported as-is; the library assigns no meaning to them.
package headerauth

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-bumbu/userauth/auth/chain"
)

// Default header names, used when Cfg leaves them empty.
const (
	UserAuthHeader   = "X-User-Auth"
	GroupsAuthHeader = "X-User-Groups"
)

const defaultGroupsSep = ","

const authName = "httpheader"

// Cfg configures the header auth handler.
type Cfg struct {
	// UserHeader carries the authenticated user identity. Defaults to
	// UserAuthHeader.
	UserHeader string
	// GroupsHeader carries the user's group list. Defaults to
	// GroupsAuthHeader. Set ParseGroups to enable group parsing.
	GroupsHeader string
	// ParseGroups enables parsing of GroupsHeader into RequestData.Groups.
	ParseGroups bool
	// GroupsSep separates group names within the groups header. Defaults to ",".
	GroupsSep string
	// Enforce stops chain evaluation when the user header is absent, making
	// this handler the final authority instead of falling through to later
	// chain handlers.
	Enforce bool
	// TrustedProxies restricts which peers may assert identity headers: when
	// non-empty, headers are honored only if the request's RemoteAddr is
	// within one of the prefixes. When empty, every peer is trusted and the
	// deployment alone must guarantee the proxy is the only path in.
	TrustedProxies []netip.Prefix
	Logger         *slog.Logger
}

// HeaderHandler authenticates requests from proxy-injected identity headers.
// It implements chain.AuthHandler.
type HeaderHandler struct {
	userHeader     string
	groupsHeader   string
	parseGroups    bool
	groupsSep      string
	enforce        bool
	trustedProxies []netip.Prefix
	logger         *slog.Logger
}

// New creates a header auth handler from the config, applying defaults for
// empty header names and separator.
func New(cfg Cfg) *HeaderHandler {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.UserHeader == "" {
		cfg.UserHeader = UserAuthHeader
	}
	if cfg.GroupsHeader == "" {
		cfg.GroupsHeader = GroupsAuthHeader
	}
	if cfg.GroupsSep == "" {
		cfg.GroupsSep = defaultGroupsSep
	}

	return &HeaderHandler{
		userHeader:     cfg.UserHeader,
		groupsHeader:   cfg.GroupsHeader,
		parseGroups:    cfg.ParseGroups,
		groupsSep:      cfg.GroupsSep,
		enforce:        cfg.Enforce,
		trustedProxies: cfg.TrustedProxies,
		logger:         cfg.Logger.With("auth-handler", authName),
	}
}

// Name implements chain.AuthHandler.
func (h *HeaderHandler) Name() string {
	return authName
}

// HandleAuth implements chain.AuthHandler. On success it stores the identity
// (user + groups) in the request context; read it with CtxGetRequestData.
func (h *HeaderHandler) HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool) {
	stopEvaluation = h.enforce

	if !h.trusted(r) {
		h.logger.Debug("header auth: untrusted peer, ignoring identity headers", "remoteAddr", r.RemoteAddr)
		return false, stopEvaluation
	}

	data := h.GetData(r)
	if data.UserName == "" {
		return false, stopEvaluation
	}

	CtxSetRequestData(r, data)
	h.logger.Debug("header auth: user authenticated", "user", data.UserName)
	return true, stopEvaluation
}

// Verify chain.AuthHandler at compile time.
var _ chain.AuthHandler = (*HeaderHandler)(nil)

// Middleware returns a header-only middleware that allows access when the
// request carries a user identity header from a trusted peer.
func (h *HeaderHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := h.HandleAuth(w, r); ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// trusted reports whether the request peer may assert identity headers.
func (h *HeaderHandler) trusted(r *http.Request) bool {
	if len(h.trustedProxies) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without a port (e.g. unix socket or tests); try as-is.
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range h.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RequestData is the identity a trusted proxy asserted for the request.
type RequestData struct {
	UserName string
	Groups   []string
}

// GetData extracts the identity headers from the request without any trust
// check; prefer CtxGetRequestData after HandleAuth ran.
func (h *HeaderHandler) GetData(r *http.Request) RequestData {
	data := RequestData{UserName: r.Header.Get(h.userHeader)}
	if !h.parseGroups {
		return data
	}
	raw := r.Header.Get(h.groupsHeader)
	if raw == "" {
		return data
	}
	for _, g := range strings.Split(raw, h.groupsSep) {
		g = strings.TrimSpace(g)
		if g != "" {
			data.Groups = append(data.Groups, g)
		}
	}
	return data
}
