package handlers

import (
	"log/slog"
	"slices"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/loginflow"
)

// PasswordTOTPCfg configures NewPasswordTOTP. Users, Session and Attempts are
// required; TOTP enables the optional second factor.
type PasswordTOTPCfg struct {
	Users   userauth.UserGetter
	Session loginflow.UserLogin
	// Attempts persists the state between password and TOTP step; required
	// when TOTP is set.
	Attempts loginflow.AttemptStore
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
	methods := []loginflow.Method{loginflow.PasswordMethod{Users: cfg.Users}}
	if cfg.TOTP != nil {
		methods = append(methods, loginflow.TOTPMethod{TOTP: cfg.TOTP})
	}
	if cfg.Recovery != nil {
		methods = append(methods, loginflow.RecoveryMethod{Codes: cfg.Recovery})
	}
	return &JSON{
		Flow: &loginflow.Flow{
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
func passwordTOTPPolicy(cfg PasswordTOTPCfg) loginflow.Policy {
	return loginflow.PolicyFunc(func(user userauth.User, satisfied []string) (bool, []string, error) {
		if !slices.Contains(satisfied, loginflow.MethodPassword) {
			return false, []string{loginflow.MethodPassword}, nil
		}
		if cfg.TOTP == nil {
			return true, nil, nil
		}
		data, err := cfg.TOTP.GetTOTP(user.Id)
		if err != nil {
			return false, nil, err
		}
		if !data.Enabled ||
			slices.Contains(satisfied, loginflow.MethodTOTP) ||
			slices.Contains(satisfied, loginflow.MethodRecovery) {
			return true, nil, nil
		}
		next := []string{loginflow.MethodTOTP}
		if cfg.Recovery != nil {
			next = append(next, loginflow.MethodRecovery)
		}
		return false, next, nil
	})
}

// EmailCodeCfg configures NewEmailCode. All fields except Logger are required.
type EmailCodeCfg struct {
	Users userauth.UserGetter
	// Codes issues and verifies the one-time codes
	// (userauth.NewVerificationCodeService).
	Codes *userauth.VerificationCodeService
	// Deliver sends the code to the user. Deliverers should queue the
	// message and return; a slow synchronous deliverer lets response timing
	// reveal whether a code was issued.
	Deliver userauth.Deliverer
	Session loginflow.UserLogin
	Logger  *slog.Logger
}

// NewEmailCode returns JSON endpoints for passwordless email-code login: the
// request-code endpoint issues and delivers a one-time code (enumeration-safe
// — the response never reveals whether the account exists), and the verify
// endpoint with method "email" completes the login.
func NewEmailCode(cfg EmailCodeCfg) *JSON {
	return &JSON{
		Flow: &loginflow.Flow{
			Users:   cfg.Users,
			Methods: []loginflow.Method{loginflow.EmailCodeMethod(cfg.Codes, cfg.Deliver)},
			Policy:  loginflow.RequireAny(loginflow.Chain{loginflow.MethodEmail}),
			Session: cfg.Session, // single factor: no attempt store needed
			Logger:  cfg.Logger,
		},
		Logger: cfg.Logger,
	}
}
