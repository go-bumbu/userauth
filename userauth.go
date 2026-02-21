package userauth

import (
	"errors"
	"fmt"

	"github.com/go-bumbu/userauth/hashutil"
	"github.com/pquerna/otp/totp"
)

type User struct {
	Id      string // user Identifying string: e.g. name or email
	HashPw  string // hashed passwd in one of the supported algorithms
	Enabled bool   // flag if user is enabled
	//MinLoginTime time.Time // can be set to a time, where all tokens/sessions created before this time are invalid
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

// TOTPGetter is the read-only interface for TOTP 2FA (authenticator app and recovery codes). LoginHandler uses only this.
type TOTPGetter interface {
	GetTOTP(userID string) (TOTPData, error)
	VerifyRecoveryCode(userID, code string) (bool, error)
}

// EmailCodeVerifier verifies a one-time email verification code at login.
type EmailCodeVerifier interface {
	VerifyEmailCode(userID, code string) (bool, error)
}

// SMSCodeVerifier verifies a one-time SMS verification code at login.
type SMSCodeVerifier interface {
	VerifySMSCode(userID, code string) (bool, error)
}

// LoginHandler checks user credentials and optional 2FA. It depends only on read interfaces (no store interface).
// Wire SecondFactors to report which 2FA methods are available for a user; wire TOTP, EmailCode, and/or SMSCode when the store supports each for verification.
type LoginHandler struct {
	UserStore     UserGetter           // user lookup for login
	SecondFactors SecondFactorProvider // optional; when set, used to determine Requires2FA and available second factors
	TOTP          TOTPGetter           // optional; when set and in AvailableSecondFactors, login can use TOTP or recovery code
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

func (lh *LoginHandler) VerifyTOTP(userID, code string) (LoginResult, error) {
	if lh.TOTP == nil {
		return LoginResult{}, fmt.Errorf("TOTP not configured")
	}

	totpData, err := lh.TOTP.GetTOTP(userID)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if !totpData.Enabled {
		return LoginResult{Authenticated: false}, fmt.Errorf("2FA not enabled for user")
	}

	ok := totp.Validate(code, totpData.Secret)
	if !ok {
		return LoginResult{Authenticated: false}, nil
	}

	return LoginResult{
		UserID:        userID,
		Authenticated: true,
	}, nil
}

// VerifyRecoveryCode verifies the given code against the user's recovery codes, consumes it on success, and returns a LoginResult.
func (lh *LoginHandler) VerifyRecoveryCode(userID, code string) (LoginResult, error) {
	if lh.TOTP == nil {
		return LoginResult{}, fmt.Errorf("TOTP not configured")
	}
	ok, err := lh.TOTP.VerifyRecoveryCode(userID, code)
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
