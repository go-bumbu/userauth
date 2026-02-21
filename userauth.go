package userauth

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
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

type TOTPGetter interface {
	GetTOTP(userID string) (TOTPData, error)
}

type LoginHandler struct {
	users UserGetter
	totp  TOTPGetter
}

// NewLoginHandler returns a LoginHandler that uses the given UserGetter for credential checks.
// Pass nil for totp to disable 2FA.
func NewLoginHandler(users UserGetter, totp TOTPGetter) *LoginHandler {
	if users == nil {
		panic("userauth: UserGetter cannot be nil")
	}
	return &LoginHandler{users: users, totp: totp}
}

type LoginResult struct {
	UserID        string
	Authenticated bool
	Requires2FA   bool
}

func (lh *LoginHandler) CanLogin(userID string, plainPw string) (LoginResult, error) {
	user, err := lh.users.GetUser(userID)
	if err != nil {
		return LoginResult{Authenticated: false}, err
	}
	if !user.Enabled {
		return LoginResult{Authenticated: false}, ErrUserDisabled
	}

	// verify password — LoginHandler owns this logic
	ok, err := CheckPass(plainPw, user.HashPw)
	if err != nil {
		return LoginResult{Authenticated: false}, nil
	}
	if !ok {
		return LoginResult{Authenticated: false}, nil
	}

	// optional: check if 2FA is required
	if lh.totp != nil {
		totpData, err := lh.totp.GetTOTP(userID)
		if err != nil {
			return LoginResult{Authenticated: false}, err
		}
		if totpData.Enabled {
			return LoginResult{
				Authenticated: false,
				UserID:        user.Id,
				Requires2FA:   true,
			}, nil
		}
	}

	return LoginResult{
		UserID:        user.Id,
		Authenticated: true,
	}, nil
}

func (lh *LoginHandler) VerifyTOTP(userID, code string) (LoginResult, error) {
	if lh.totp == nil {
		return LoginResult{}, fmt.Errorf("2FA not configured")
	}

	totpData, err := lh.totp.GetTOTP(userID)
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

// ErrUserNotFound is thrown when a user is not found
var ErrUserNotFound = errors.New("user not found")

// ErrUserDisabled is thrown when a user is not enabled
var ErrUserDisabled = errors.New("user is not enabled")

// CheckPass compares a provided transient password (that is never stored) with the stored counterpart hash
func CheckPass(plainPass, hash string) (bool, error) {
	switch Alg(hash) {
	case Bcrypt:
		ok, err := checkBcryptPw(plainPass, hash)
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil
			}
			return false, err
		}
		return ok, nil
	default:
		return false, fmt.Errorf("unknown crypto algorithm")
	}
}

func checkBcryptPw(plainPass, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPass))
	if err != nil {
		return false, err
	}
	return true, nil
}

type HashAlgo int

const (
	Unknown = iota
	Bcrypt
)

func Alg(hash string) HashAlgo {
	if isbCryptString(hash) {
		return Bcrypt
	}
	return Unknown
}

// HashPw creates a hash encrypted password of the provided string
func HashPw(pw string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(bytes), err
}
func MustHashPw(pw string) string {
	hash, err := HashPw(pw)
	if err != nil {
		panic(err)
	}
	return hash
}

const (
	BCryp1PRefix = "$2$"
	BCryp2PRefix = "$2a$"
	BCryp3PRefix = "$2b$"
	BCryp4PRefix = "$2x$"
	BCryp5PRefix = "$2y$"
)

var bCryptPrefix = []string{
	BCryp2PRefix,
	BCryp3PRefix,
	BCryp4PRefix,
	BCryp5PRefix,
}

func isbCryptString(hash string) bool {
	if strings.HasPrefix(hash, BCryp1PRefix) {
		return true
	}
	if len(hash) >= 3 && slices.Contains(bCryptPrefix, hash[:4]) {
		return true
	}
	return false
}
