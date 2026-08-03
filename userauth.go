package userauth

import (
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"github.com/go-bumbu/userauth/internal/hashutil"
)

// UsernameFormat is the policy for allowed login identifier format (e.g. email-only or plain).
type UsernameFormat int8

const (
	UsernameFormatAny   UsernameFormat = 0 // any value
	UsernameFormatEmail UsernameFormat = 1 // must be valid email
	UsernameFormatPlain UsernameFormat = 2 // must not be email
)

// String returns the API string for the format ("any", "email", "plain").
func (f UsernameFormat) String() string {
	switch f {
	case UsernameFormatEmail:
		return "email"
	case UsernameFormatPlain:
		return "plain"
	default:
		return "any"
	}
}

// ParseUsernameFormat parses config string into UsernameFormat. Accepts "any", "email", "plain" (case-insensitive) or "0", "1", "2".
func ParseUsernameFormat(s string) UsernameFormat {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "email", "1":
		return UsernameFormatEmail
	case "plain", "2":
		return UsernameFormatPlain
	case "any", "0", "":
		return UsernameFormatAny
	default:
		if n, err := strconv.ParseInt(s, 10, 8); err == nil && n >= 0 && n <= 2 {
			return UsernameFormat(n)
		}
		return UsernameFormatAny
	}
}

// ValidateLoginID returns an error if loginID does not conform to the format (e.g. email-only or must not be email).
func ValidateLoginID(loginID string, format UsernameFormat) error {
	switch format {
	case UsernameFormatEmail:
		_, err := mail.ParseAddress(loginID)
		if err != nil {
			return fmt.Errorf("username must be a valid email address")
		}
	case UsernameFormatPlain:
		if strings.Contains(loginID, "@") {
			return fmt.Errorf("username must not be an email address")
		}
	default:
		// Any or unknown: no restriction
	}
	return nil
}

type User struct {
	Id                   string // login identifier (same as loginId in store)
	HashPw               string // hashed passwd in one of the supported algorithms
	Enabled              bool   // flag if user is enabled
	PrimaryEmail         string // primary email address
	PrimaryEmailVerified bool   // whether primary email has been verified
	BackupEmail          string // backup email address
	BackupEmailVerified  bool   // whether backup email has been verified
}

type UserGetter interface {
	GetUser(id string) (User, error)
}

type TOTPData struct {
	Enabled bool
	Secret  string // the shared secret for TOTP generation
}

// SecondFactor is a kind of second factor that can be required at login.
type SecondFactor string

const (
	SecondFactorTOTP  SecondFactor = "totp"
	SecondFactorEmail SecondFactor = "email"
	SecondFactorSMS   SecondFactor = "sms"
)

// SecondFactorProvider returns the list of second factors enabled for a user.
// loginflow policies use this to decide whether a second factor is required.
type SecondFactorProvider interface {
	AvailableSecondFactors(userID string) ([]SecondFactor, error)
}

// TOTPGetter is the read-only interface for TOTP 2FA (authenticator app). loginflow.TOTPMethod uses this for TOTP verification.
type TOTPGetter interface {
	GetTOTP(userID string) (TOTPData, error)
}

// RecoveryCodeVerifier verifies a recovery code at login. Separate from TOTP; stores may implement one or both.
type RecoveryCodeVerifier interface {
	VerifyRecoveryCode(userID, code string) (bool, error)
}

// UserRegistrar can create new users. When the user store implements this, registration (e.g. POST /register) can be offered.
type UserRegistrar interface {
	Create(id string, pw string) error
}

// UserUpdater can update user fields (email, enabled state). Stores that support
// user profile management implement this.
type UserUpdater interface {
	SetPrimaryEmail(userID, email string) error
	SetPrimaryEmailVerified(userID string, verified bool) error
	SetEnabled(userID string, enabled bool) error
}

// TOTPConfigurator can read and write TOTP for a user. Stores that support TOTP setup/disable implement this.
type TOTPConfigurator interface {
	TOTPGetter
	SetTOTP(userID string, data TOTPData) error
}

// RecoveryCodeConfigurator can write recovery codes for a user. Stores that support recovery code setup implement this.
type RecoveryCodeConfigurator interface {
	// SetRecoveryCodes replaces all recovery codes for the user with the given bcrypt-hashed codes (from hashutil.HashRecoveryCode).
	SetRecoveryCodes(userID string, hashedCodes []string) error
}

// RecoveryCodeCountGetter returns the number of remaining (unused) recovery codes for a user.
type RecoveryCodeCountGetter interface {
	GetRecoveryCodesCount(userID string) (int, error)
}

// ErrUserNotFound is thrown when a user is not found
var ErrUserNotFound = errors.New("user not found")

// ErrUserDisabled is thrown when a user is not enabled
var ErrUserDisabled = errors.New("user is not enabled")

// CheckPass compares a plain password with a stored hash. Returns true if they match.
func CheckPass(plainPass, hash string) (bool, error) {
	return hashutil.VerifyPassword(plainPass, hash)
}

// MustHashPw returns a bcrypt hash of the password; panics on error.
func MustHashPw(pw string) string {
	return hashutil.MustHashPassword(pw)
}
