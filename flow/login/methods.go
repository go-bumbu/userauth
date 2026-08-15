package login

import (
	"context"
	"errors"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"github.com/go-bumbu/userauth/service/verificationcode"
	"github.com/pquerna/otp/totp"
)

// Well-known method IDs. Policies and transports refer to methods by these
// strings; custom methods may introduce their own.
const (
	MethodPassword = "password"
	MethodTOTP     = "totp"
	MethodEmail    = "email"
	MethodSMS      = "sms"
	MethodRecovery = "recovery"
)

// Method verifies a single login factor.
//
// Verify must return (false, nil) for wrong input and reserve errors for
// internal failures — the engine maps errors to 5xx-shaped results, never to
// "try again".
type Method interface {
	ID() string
	Verify(userID, input string) (bool, error)
}

// Initiator is the optional issuance side of a deliverable factor: generate a
// code, persist it, deliver it. Methods that need a prior server action
// (email, SMS) implement it; password and TOTP do not.
type Initiator interface {
	Initiate(ctx context.Context, user userauth.User) error
}

// --- password ---

// PasswordMethod verifies the stored password hash. It reuses the same user
// lookup as the engine; the engine has already established that the user
// exists and is enabled, and hands over the canonical user ID.
type PasswordMethod struct {
	Users userauth.UserGetter
}

func (m PasswordMethod) ID() string { return MethodPassword }

func (m PasswordMethod) Verify(userID, input string) (bool, error) {
	user, err := m.Users.GetUser(userID)
	if err != nil {
		if errors.Is(err, userauth.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	ok, err := hashutil.VerifyPassword(input, user.HashPw)
	if err != nil {
		// malformed/absent hash: credential failure, not an internal error
		return false, nil
	}
	return ok, nil
}

// --- totp ---

// TOTPMethod verifies an authenticator-app code.
//
// Throttle should always be set outside of tests: TOTP codes are 6 digits, so
// without verifier-side throttling the keyspace is brute-forceable within a
// code's validity window (RFC 6238 §5.2 requires the throttle).
type TOTPMethod struct {
	TOTP     userauth.TOTPGetter
	Throttle *Throttle
}

func (m TOTPMethod) ID() string { return MethodTOTP }

func (m TOTPMethod) Verify(userID, input string) (bool, error) {
	data, err := m.TOTP.GetTOTP(userID)
	if err != nil {
		return false, err
	}
	if !data.Enabled {
		return false, nil
	}
	return throttled(m.Throttle, userID, MethodTOTP, func() (bool, error) {
		return totp.Validate(input, data.Secret), nil
	})
}

// --- recovery ---

// RecoveryMethod verifies a single-use recovery code. Throttle should be set
// outside of tests: recovery codes are a small fixed set of short strings.
type RecoveryMethod struct {
	Codes    userauth.RecoveryCodeVerifier
	Throttle *Throttle
}

func (m RecoveryMethod) ID() string { return MethodRecovery }

func (m RecoveryMethod) Verify(userID, input string) (bool, error) {
	return throttled(m.Throttle, userID, MethodRecovery, func() (bool, error) {
		return m.Codes.VerifyRecoveryCode(userID, input)
	})
}

// throttled runs verify under the throttle: a delayed attempt is rejected as
// a credential failure without invoking the verifier, a wrong guess is
// recorded, and a correct one clears the failure state. A nil throttle runs
// the verifier directly.
func throttled(t *Throttle, userID, method string, verify func() (bool, error)) (bool, error) {
	if t == nil {
		return verify()
	}
	allowed, err := t.Allow(userID, method)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, nil
	}
	ok, err := verify()
	if err != nil {
		return false, err
	}
	if !ok {
		if err := t.Fail(userID, method); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := t.Success(userID, method); err != nil {
		return false, err
	}
	return true, nil
}

// --- delivered one-time codes (email, sms) ---

// CodeIssuer generates and persists a one-time code for a user.
// *verificationcode.Service satisfies this.
type CodeIssuer interface {
	Generate(userID string) (code string, expiresAt time.Time, err error)
}

// CodeMethod is a delivered one-time-code factor (email or SMS). It verifies
// via a verificationcode.CodeVerifier and initiates by generating a code and
// handing it to a Deliverer.
type CodeMethod struct {
	MethodID string // MethodEmail, MethodSMS, or a custom ID
	Verifier verificationcode.CodeVerifier
	Issuer   CodeIssuer
	Deliver  verificationcode.Deliverer
	// Recipient resolves the delivery address for a user (e.g. a phone number
	// for SMS). When nil, the primary email is used, falling back to the login
	// ID for stores that keep the address there.
	Recipient func(userauth.User) string
}

func (m CodeMethod) ID() string { return m.MethodID }

func (m CodeMethod) Verify(userID, input string) (bool, error) {
	return m.Verifier.Verify(userID, input)
}

// Initiate generates, stores and delivers a fresh code. It implements
// Initiator; the engine only calls it for known, enabled users. The code is
// keyed by the canonical user ID; delivery goes to the resolved recipient.
func (m CodeMethod) Initiate(ctx context.Context, user userauth.User) error {
	code, expiresAt, err := m.Issuer.Generate(user.ID)
	if err != nil {
		return err
	}
	return m.Deliver.Deliver(ctx, m.recipient(user), code, expiresAt)
}

func (m CodeMethod) recipient(user userauth.User) string {
	if m.Recipient != nil {
		return m.Recipient(user)
	}
	if user.PrimaryEmail != "" {
		return user.PrimaryEmail
	}
	return user.LoginID
}

// EmailCodeMethod wires a CodeMethod for the common email case, using the
// verification code service as both issuer and verifier.
func EmailCodeMethod(codes *verificationcode.Service, deliver verificationcode.Deliverer) CodeMethod {
	return CodeMethod{MethodID: MethodEmail, Verifier: codes, Issuer: codes, Deliver: deliver}
}
