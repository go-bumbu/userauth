package totp

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Verifier is the login-side view of a TOTP factor: verify a code, and report
// whether the user has the factor at all so a policy can decide to ask for it.
// *Service implements it, and FromGetter adapts read-only stores that expose
// only a secret.
type Verifier interface {
	Verify(userID, code string) (bool, error)
	Enabled(userID string) (bool, error)
}

var _ Verifier = (*Service)(nil)

// Verify checks an authenticator code against the user's confirmed secret.
//
// It returns (false, nil) for every "no" a user can cause — wrong code, pending
// enrolment, no enrolment at all — and reserves errors for store and cipher
// failures, so callers cannot accidentally turn a missing factor into a 500.
//
// Single-use per period is deliberately not enforced: TOTP codes stay valid for
// their whole window by design, and replay within that window is bounded by the
// caller's throttle (see flow/login.TOTPMethod).
func (s *Service) Verify(userID, code string) (bool, error) {
	rec, err := s.store.Get(userID)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return false, nil
		}
		return false, err
	}
	if !rec.Enabled {
		return false, nil
	}
	secret, err := s.decrypt(rec)
	if err != nil {
		return false, err
	}
	return validateCode(code, secret, s.skew), nil
}

func (s *Service) validate(code, secret string) bool {
	return validateCode(code, secret, s.skew)
}

// validateCode checks a code against a base32 secret, accepting skew periods
// either side of now. A malformed code or secret is a credential failure, not
// an internal one, so errors collapse to false.
func validateCode(code, secret string, skew uint) bool {
	if code == "" || secret == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      skew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return ok
}

// FromGetter adapts a userauth.TOTPGetter into a Verifier, for read-only user
// stores (e.g. userstore/staticusers) that hold the secret themselves and have
// no enrolment lifecycle. Enrolment is not available through this path: those
// secrets are provisioned out of band.
//
// skew is the accepted clock drift in 30-second periods; 0 uses DefaultSkew.
func FromGetter(get userauth.TOTPGetter, skew uint) (Verifier, error) {
	if get == nil {
		return nil, fmt.Errorf("totp: getter is required")
	}
	if skew == 0 {
		skew = DefaultSkew
	}
	return getterVerifier{get: get, skew: skew}, nil
}

// getterVerifier verifies against a userauth.TOTPGetter. It carries no state
// and never writes.
type getterVerifier struct {
	get  userauth.TOTPGetter
	skew uint
}

var _ Verifier = getterVerifier{}

func (g getterVerifier) Verify(userID, code string) (bool, error) {
	data, err := g.get.GetTOTP(userID)
	if err != nil {
		return false, err
	}
	if !data.Enabled {
		return false, nil
	}
	return validateCode(code, data.Secret, g.skew), nil
}

func (g getterVerifier) Enabled(userID string) (bool, error) {
	data, err := g.get.GetTOTP(userID)
	if err != nil {
		return false, err
	}
	return data.Enabled, nil
}

// buildURI assembles an otpauth:// URI for a known secret. Enroll gets its URI
// from the generated key; this is for re-rendering a pending enrolment.
func buildURI(issuer, accountName, secret string) (string, error) {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + accountName,
		RawQuery: v.Encode(),
	}
	// parse back through the otp library so a malformed issuer or account name
	// fails here rather than in the user's authenticator app
	if _, err := otp.NewKeyFromURL(u.String()); err != nil {
		return "", fmt.Errorf("totp: build otpauth URI: %w", err)
	}
	return u.String(), nil
}
