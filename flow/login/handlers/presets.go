package handlers

import (
	"log/slog"
	"slices"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/login"
	"github.com/go-bumbu/userauth/service/verificationcode"
)

// PasswordTOTPCfg configures NewPasswordTOTP. Users, Session and Attempts are
// required; TOTP enables the optional second factor.
type PasswordTOTPCfg struct {
	Users   userauth.UserGetter
	Session login.UserLogin
	// Attempts persists the state between password and TOTP step; required
	// when TOTP is set.
	Attempts login.AttemptStore
	// TOTP enables an authenticator second factor for users that have one
	// enrolled (data.Enabled). Nil means password-only login.
	TOTP userauth.TOTPGetter
	// Recovery optionally lets a recovery code stand in for the TOTP code.
	Recovery userauth.RecoveryCodeVerifier
	Logger   *slog.Logger
}

// NewPasswordTOTP returns JSON endpoints for username+password login with an
// optional TOTP second factor: password-only users complete at the login
// endpoint, users with TOTP enrolled get {"done":false,"next":["totp",...]}
// and complete at the verify endpoint with a TOTP — or, when configured, a
// recovery — code.
func NewPasswordTOTP(cfg PasswordTOTPCfg) *JSON {
	methods := []login.Method{login.PasswordMethod{Users: cfg.Users}}
	if cfg.TOTP != nil {
		methods = append(methods, login.TOTPMethod{TOTP: cfg.TOTP})
	}
	if cfg.Recovery != nil {
		methods = append(methods, login.RecoveryMethod{Codes: cfg.Recovery})
	}
	return &JSON{
		Flow: &login.Flow{
			Users:    cfg.Users,
			Methods:  methods,
			Policy:   passwordTOTPPolicy(cfg),
			Attempts: cfg.Attempts,
			Session:  cfg.Session,
			Logger:   cfg.Logger,
		},
		Logger: cfg.Logger,
	}
}

// passwordTOTPPolicy requires the password and then, only for users with TOTP
// enrolled, an authenticator code — or a recovery code when configured.
func passwordTOTPPolicy(cfg PasswordTOTPCfg) login.Policy {
	return login.PolicyFunc(func(user userauth.User, satisfied []string) (bool, []string, error) {
		if !slices.Contains(satisfied, login.MethodPassword) {
			return false, []string{login.MethodPassword}, nil
		}
		if cfg.TOTP == nil {
			return true, nil, nil
		}
		data, err := cfg.TOTP.GetTOTP(user.ID)
		if err != nil {
			return false, nil, err
		}
		if !data.Enabled ||
			slices.Contains(satisfied, login.MethodTOTP) ||
			slices.Contains(satisfied, login.MethodRecovery) {
			return true, nil, nil
		}
		next := []string{login.MethodTOTP}
		if cfg.Recovery != nil {
			next = append(next, login.MethodRecovery)
		}
		return false, next, nil
	})
}

// EmailCodeCfg configures NewEmailCode. All fields except Logger are required.
type EmailCodeCfg struct {
	Users userauth.UserGetter
	// Codes issues and verifies the one-time codes
	// (verificationcode.NewService).
	Codes *verificationcode.Service
	// Deliver sends the code to the user. Deliverers should queue the
	// message and return; a slow synchronous deliverer lets response timing
	// reveal whether a code was issued.
	Deliver verificationcode.Deliverer
	Session login.UserLogin
	Logger  *slog.Logger
}

// NewEmailCode returns JSON endpoints for passwordless email-code login: the
// request-code endpoint issues and delivers a one-time code (enumeration-safe
// — the response never reveals whether the account exists), and the verify
// endpoint with method "email" completes the login.
func NewEmailCode(cfg EmailCodeCfg) *JSON {
	return &JSON{
		Flow: &login.Flow{
			Users:   cfg.Users,
			Methods: []login.Method{login.EmailCodeMethod(cfg.Codes, cfg.Deliver)},
			Policy:  login.RequireAny(login.Chain{login.MethodEmail}),
			Session: cfg.Session, // single factor: no attempt store needed
			Logger:  cfg.Logger,
		},
		Logger: cfg.Logger,
	}
}
