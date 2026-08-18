// Package secondfactor composes a userauth.SecondFactorProvider out of one
// availability check per factor.
//
// Which factors a login can require then becomes a wiring decision rather than
// a property of the user store: a setup that wires only TOTP reports only TOTP,
// and never touches an email or SMS table it does not have. This replaces the
// user store answering for every factor kind it might one day support.
package secondfactor

import (
	"fmt"

	"github.com/go-bumbu/userauth"
)

// Availability reports whether a user has a factor ready to use at login.
// "Ready" means enrolled and confirmed: a pending TOTP enrolment is not
// available, because the user cannot produce codes for it yet.
type Availability interface {
	Available(userID string) (bool, error)
}

// Provider answers userauth.SecondFactorProvider by asking each wired
// Availability. A nil field means the factor is not wired at all and is never
// probed. The order is fixed (TOTP, email, SMS) so login policies see a stable
// factor list.
type Provider struct {
	TOTP  Availability
	Email Availability
	SMS   Availability
}

var _ userauth.SecondFactorProvider = Provider{}

// AvailableSecondFactors implements userauth.SecondFactorProvider. A failing
// check is returned as an error rather than swallowed as "not available":
// silently dropping a required factor would weaken the login.
func (p Provider) AvailableSecondFactors(userID string) ([]userauth.SecondFactor, error) {
	checks := []struct {
		kind  userauth.SecondFactor
		check Availability
	}{
		{userauth.SecondFactorTOTP, p.TOTP},
		{userauth.SecondFactorEmail, p.Email},
		{userauth.SecondFactorSMS, p.SMS},
	}

	var out []userauth.SecondFactor
	for _, c := range checks {
		if c.check == nil {
			continue
		}
		ok, err := c.check.Available(userID)
		if err != nil {
			return nil, fmt.Errorf("check %s availability: %w", c.kind, err)
		}
		if ok {
			out = append(out, c.kind)
		}
	}
	return out, nil
}
