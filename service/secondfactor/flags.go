package secondfactor

import "github.com/go-bumbu/userauth"

// Store persists which optional second factors a user has turned on.
//
// It exists for factors whose availability is a user preference rather than an
// enrolment artefact: an email or SMS code needs no per-user secret, so nothing
// else records that the user wants it. TOTP needs no entry here — the presence
// of a confirmed enrolment is the flag.
//
// Implementations are pure persistence and treat the factor as an opaque label.
type Store interface {
	// Enabled reports whether the user turned the factor on. A user with no
	// row for the factor returns false, not an error: never having chosen is
	// the same as having it off.
	Enabled(userID string, factor userauth.SecondFactor) (bool, error)
	// SetEnabled turns the factor on or off for the user.
	SetEnabled(userID string, factor userauth.SecondFactor, enabled bool) error
}

// Flag adapts one factor of a Store to Availability, so a stored preference can
// drive Provider.Email or Provider.SMS.
type Flag struct {
	Store  Store
	Factor userauth.SecondFactor
}

var _ Availability = Flag{}

// Available implements Availability by reading the user's stored preference.
func (f Flag) Available(userID string) (bool, error) {
	return f.Store.Enabled(userID, f.Factor)
}
