package handlers

import (
	"log/slog"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/register"
)

// Cfg configures New. Users and Creator are required; the optional fields
// compose the registration requirements additively:
//
//   - Codes + Deliver enable email verification (requires Pending)
//   - Invites enables invite-code gating
//   - neither: open registration
type Cfg struct {
	Users   userauth.UserGetter   // required: login ID availability
	Creator register.UserCreator  // required: creates the account
	Pending register.PendingStore // required when Codes is set

	// Codes issues and verifies the email verification codes
	// (userauth.NewVerificationCodeService). Nil disables email verification.
	Codes *userauth.VerificationCodeService
	// Deliver sends the code to the user; required with Codes. Deliverers
	// should queue the message and return.
	Deliver userauth.Deliverer

	// Invites gates registration behind invite codes (*invite.Service
	// satisfies this). Nil disables invite gating.
	Invites register.InviteConsumer

	Password       register.PasswordValidator // optional; default requires non-empty
	UsernameFormat userauth.UsernameFormat
	Session        register.SessionCreator // optional: auto-login after registration
	Expiry         time.Duration           // pending lifetime; default register.DefaultPendingExpiry
	Logger         *slog.Logger
}

// New returns JSON endpoints for self-registration, composing the checks
// from what is configured: open registration, email verification, invite
// gating, or both.
func New(cfg Cfg) *JSON {
	var checks []register.Check
	if cfg.Invites != nil {
		checks = append(checks, register.InviteCheck{Invites: cfg.Invites})
	}
	if cfg.Codes != nil {
		checks = append(checks, register.EmailCheck{Codes: cfg.Codes, Deliver: cfg.Deliver})
	}
	return &JSON{
		Flow: &register.Flow{
			Users:          cfg.Users,
			Creator:        cfg.Creator,
			Checks:         checks,
			Pending:        cfg.Pending,
			Password:       cfg.Password,
			UsernameFormat: cfg.UsernameFormat,
			Session:        cfg.Session,
			Expiry:         cfg.Expiry,
			Logger:         cfg.Logger,
		},
		Logger: cfg.Logger,
	}
}
