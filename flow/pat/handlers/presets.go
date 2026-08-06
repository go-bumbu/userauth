package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	flowpat "github.com/go-bumbu/userauth/flow/pat"
	patsvc "github.com/go-bumbu/userauth/service/pat"
)

// Cfg wires the JSON endpoints.
type Cfg struct {
	// Service owns token policy. Required.
	Service *patsvc.Service
	// UserID extracts the authenticated user from the request. Optional:
	// defaults to reading the cookieauth session context, which requires
	// the endpoints to be mounted behind cookieauth session middleware.
	UserID func(r *http.Request) (string, error)
	Logger *slog.Logger
}

// New returns JSON endpoints for PAT management.
func New(cfg Cfg) *JSON {
	if cfg.UserID == nil {
		cfg.UserID = cookieSessionUserID
	}
	return &JSON{
		Flow: &flowpat.Flow{
			Service: cfg.Service,
			UserID:  cfg.UserID,
		},
		Logger: cfg.Logger,
	}
}

// cookieSessionUserID reads the user from the cookieauth session context.
func cookieSessionUserID(r *http.Request) (string, error) {
	ud, err := cookieauth.CtxGetUserData(r)
	if err != nil {
		return "", err
	}
	return ud.UserId, nil
}
