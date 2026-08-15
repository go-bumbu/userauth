package handlers

import (
	"log/slog"
	"slices"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/login"
	throttlememory "github.com/go-bumbu/userauth/service/throttle/store/memory"
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
	// Throttle slows down repeated wrong TOTP/recovery guesses, and (via
	// login.ThrottleGuard) wrong passwords per login identifier. Nil gets an
	// in-memory throttle with the package defaults — per-instance state, so
	// multi-instance deployments should pass a Throttle backed by
	// throttlestore/db. It cannot be disabled: 6-digit codes are
	// brute-forceable without one.
	Throttle *login.Throttle
	Logger   *slog.Logger
}

// NewPasswordTOTP returns JSON endpoints for username+password login with an
// optional TOTP second factor: password-only users complete at the login
// endpoint, users with TOTP enrolled get {"done":false,"next":["totp",...]}
// and complete at the verify endpoint with a TOTP — or, when configured, a
// recovery — code.
func NewPasswordTOTP(cfg PasswordTOTPCfg) *JSON {
	if cfg.Throttle == nil {
		cfg.Throttle = &login.Throttle{Store: throttlememory.New()}
	}
	methods := []login.Method{login.PasswordMethod{Users: cfg.Users}}
	if cfg.TOTP != nil {
		methods = append(methods, login.TOTPMethod{TOTP: cfg.TOTP, Throttle: cfg.Throttle})
	}
	if cfg.Recovery != nil {
		methods = append(methods, login.RecoveryMethod{Codes: cfg.Recovery, Throttle: cfg.Throttle})
	}
	return &JSON{
		Flow: &login.Flow{
			Users:    cfg.Users,
			Methods:  methods,
			Policy:   passwordTOTPPolicy(cfg),
			Attempts: cfg.Attempts,
			Session:  cfg.Session,
			Guard:    login.ThrottleGuard{Throttle: cfg.Throttle},
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
	// Resend bounds how often the request-code endpoint issues a code per
	// user. Nil gets an in-memory limiter with the package defaults —
	// per-instance state, so multi-instance deployments should pass one
	// backed by throttlestore/db. It cannot be disabled: an unlimited
	// endpoint is an email-bombing relay.
	Resend *login.ResendLimiter
	// Guard throttles verify submissions per login identifier (covering
	// unknown accounts too — wrong codes for existing users are already
	// capped per issued code). Nil gets a ThrottleGuard sharing the Resend
	// limiter's store.
	Guard  login.Guard
	Logger *slog.Logger
}

// NewEmailCode returns JSON endpoints for passwordless email-code login: the
// request-code endpoint issues and delivers a one-time code (enumeration-safe
// — the response never reveals whether the account exists), and the verify
// endpoint with method "email" completes the login.
func NewEmailCode(cfg EmailCodeCfg) *JSON {
	if cfg.Resend == nil {
		cfg.Resend = &login.ResendLimiter{Store: throttlememory.New()}
	}
	if cfg.Guard == nil {
		cfg.Guard = login.ThrottleGuard{Throttle: &login.Throttle{Store: cfg.Resend.Store}}
	}
	return &JSON{
		Flow: &login.Flow{
			Users:   cfg.Users,
			Methods: []login.Method{login.EmailCodeMethod(cfg.Codes, cfg.Deliver)},
			Policy:  login.RequireAny(login.Chain{login.MethodEmail}),
			Session: cfg.Session, // single factor: no attempt store needed
			Resend:  cfg.Resend,
			Guard:   cfg.Guard,
			Logger:  cfg.Logger,
		},
		Logger: cfg.Logger,
	}
}
