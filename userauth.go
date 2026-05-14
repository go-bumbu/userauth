package userauth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/go-bumbu/userauth/hashutil"
	"github.com/pquerna/otp/totp"
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

// SecondFactorProvider returns the list of second factors enabled for a user. LoginHandler uses this to decide Requires2FA and to expose available options.
type SecondFactorProvider interface {
	AvailableSecondFactors(userID string) ([]SecondFactor, error)
}

// TOTPGetter is the read-only interface for TOTP 2FA (authenticator app). LoginHandler uses this for TOTP verification.
type TOTPGetter interface {
	GetTOTP(userID string) (TOTPData, error)
}

// RecoveryCodeVerifier verifies a recovery code at login. Separate from TOTP; stores may implement one or both.
type RecoveryCodeVerifier interface {
	VerifyRecoveryCode(userID, code string) (bool, error)
}

// UserRegistrar can create new users. When a LoginHandler's UserStore implements this, registration (e.g. POST /register) can be offered.
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

// EmailCodeVerifier verifies a one-time email verification code at login.
type EmailCodeVerifier interface {
	VerifyEmailCode(userID, code string) (bool, error)
}

// SMSCodeVerifier verifies a one-time SMS verification code at login.
type SMSCodeVerifier interface {
	VerifySMSCode(userID, code string) (bool, error)
}

// Deliverer sends a verification code to a recipient. The interface is
// transport-agnostic: implementations decide how to format and deliver the
// message (email, SMS, file, Slack, etc.).
type Deliverer interface {
	Deliver(ctx context.Context, to string, code string, expiresAt time.Time) error
}

// LoginHandler checks user credentials and optional 2FA. It depends only on read interfaces (no store interface).
// Wire SecondFactors to report which 2FA methods are available for a user; wire TOTP, RecoveryCode, EmailCode, and/or SMSCode when the store supports each for verification.
type LoginHandler struct {
	UserStore     UserGetter           // user lookup for login
	SecondFactors SecondFactorProvider // optional; when set, used to determine Requires2FA and available second factors
	TOTP          TOTPGetter           // optional; when set and in AvailableSecondFactors, login can use TOTP
	RecoveryCode  RecoveryCodeVerifier // optional; when set, login can use recovery codes (typically alongside TOTP)
	EmailCode     EmailCodeVerifier    // optional; verify email verification code
	SMSCode       SMSCodeVerifier      // optional; verify SMS verification code
}

type LoginResult struct {
	UserID                 string
	Authenticated          bool
	Requires2FA            bool
	AvailableSecondFactors []SecondFactor // set when Requires2FA is true; which methods the user can use
}

func (lh *LoginHandler) CanLogin(userID string, plainPw string) (LoginResult, error) {
	user, err := lh.UserStore.GetUser(userID)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if !user.Enabled {
		return LoginResult{Authenticated: false}, ErrUserDisabled
	}

	// verify password using hashutil
	ok, err := hashutil.VerifyPassword(plainPw, user.HashPw)
	if err != nil {
		return LoginResult{Authenticated: false}, nil
	}
	if !ok {
		return LoginResult{Authenticated: false}, nil
	}

	// optional: check if 2FA is required via single provider
	if lh.SecondFactors != nil {
		available, err := lh.SecondFactors.AvailableSecondFactors(userID)
		if err != nil {
			return LoginResult{Authenticated: false}, err
		}
		if len(available) > 0 {
			return LoginResult{
				Authenticated:          false,
				UserID:                 user.Id,
				Requires2FA:            true,
				AvailableSecondFactors: available,
			}, nil
		}
	}

	return LoginResult{
		UserID:        user.Id,
		Authenticated: true,
	}, nil
}

// VerifyTOTP verifies the code as TOTP (authenticator app) only.
func (lh *LoginHandler) VerifyTOTP(userID, code string) (LoginResult, error) {
	if lh.TOTP == nil {
		return LoginResult{}, fmt.Errorf("TOTP not configured")
	}
	totpData, err := lh.TOTP.GetTOTP(userID)
	if err != nil || !totpData.Enabled {
		return LoginResult{Authenticated: false}, nil
	}
	if totp.Validate(code, totpData.Secret) {
		return LoginResult{UserID: userID, Authenticated: true}, nil
	}
	return LoginResult{Authenticated: false}, nil
}

// VerifyRecoveryCode verifies the code as a recovery code only.
func (lh *LoginHandler) VerifyRecoveryCode(userID, code string) (LoginResult, error) {
	if lh.RecoveryCode == nil {
		return LoginResult{}, fmt.Errorf("recovery codes not configured")
	}
	ok, err := lh.RecoveryCode.VerifyRecoveryCode(userID, code)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if ok {
		return LoginResult{UserID: userID, Authenticated: true}, nil
	}
	return LoginResult{Authenticated: false}, nil
}

// VerifyEmailCode verifies the given email verification code, consumes it on success, and returns a LoginResult.
func (lh *LoginHandler) VerifyEmailCode(userID, code string) (LoginResult, error) {
	if lh.EmailCode == nil {
		return LoginResult{}, fmt.Errorf("email verification not configured")
	}
	ok, err := lh.EmailCode.VerifyEmailCode(userID, code)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if !ok {
		return LoginResult{Authenticated: false}, nil
	}
	return LoginResult{
		UserID:        userID,
		Authenticated: true,
	}, nil
}

// VerifySMSCode verifies the given SMS verification code, consumes it on success, and returns a LoginResult.
func (lh *LoginHandler) VerifySMSCode(userID, code string) (LoginResult, error) {
	if lh.SMSCode == nil {
		return LoginResult{}, fmt.Errorf("SMS verification not configured")
	}
	ok, err := lh.SMSCode.VerifySMSCode(userID, code)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if !ok {
		return LoginResult{Authenticated: false}, nil
	}
	return LoginResult{
		UserID:        userID,
		Authenticated: true,
	}, nil
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

// VerificationCodeService generates and stores one-time verification codes (email, SMS).
// It separates domain logic (code length, expiry, hashing) from storage.
type VerificationCodeService struct {
	Store      func(userID, hash string, expiresAt time.Time) error
	CodeLength int
	Expiry     time.Duration
}

// Generate creates a new numeric code, hashes it with SHA-256, stores it, and returns the plain code and expiry.
func (s *VerificationCodeService) Generate(userID string) (string, time.Time, error) {
	code, err := hashutil.GenerateNumericCode(s.CodeLength)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(s.Expiry)
	hash := hashutil.HashCodeSHA256(code)
	if err := s.Store(userID, hash, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return code, expiresAt, nil
}
