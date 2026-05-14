package staticusers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-bumbu/userauth"
	"gopkg.in/yaml.v3"
)

// ensure the interfaces are fulfilled
var _ userauth.UserGetter = &Users{}
var _ userauth.TOTPGetter = &Users{}
var _ userauth.RecoveryCodeVerifier = &Users{}
var _ userauth.SecondFactorProvider = &Users{}

type User struct {
	Id         string `yaml:"id" json:"id"`                   // user identifying string: e.g. name or email
	HashPw     string `yaml:"pw" json:"pw"`                   // hashed password in one of the supported algorithms
	Enabled    bool   `yaml:"enabled" json:"enabled"`         // flag if user is enabled
	TOTPSecret string `yaml:"totp_secret" json:"totp_secret"` // base32 TOTP secret (optional); non-empty means TOTP available
	Email2FA   string `yaml:"email_2fa" json:"email_2fa"`     // email address for email 2FA (optional); non-empty means email 2FA available
}

// TODO: add option to allow plaintext passwords in files,
// and in consequence hash on init

// Users holds a static user list. 2FA availability is derived from data presence: TOTPSecret non-empty means TOTP available, Email2FA non-empty means email 2FA available.
type Users struct {
	Users []User `yaml:"users"`
}

func (stu *Users) GetUser(userId string) (userauth.User, error) {
	for _, u := range stu.Users {
		if userId == u.Id {
			return userauth.User{
				Id:           u.Id,
				HashPw:       u.HashPw,
				Enabled:      u.Enabled,
				PrimaryEmail: u.Email2FA,
			}, nil
		}
	}
	return userauth.User{}, userauth.ErrUserNotFound
}

// GetTOTP implements userauth.TOTPGetter. Enabled derived from TOTPSecret presence.
func (stu *Users) GetTOTP(userID string) (userauth.TOTPData, error) {
	for _, u := range stu.Users {
		if u.Id == userID {
			return userauth.TOTPData{
				Enabled: u.TOTPSecret != "",
				Secret:  u.TOTPSecret,
			}, nil
		}
	}
	return userauth.TOTPData{Enabled: false}, nil
}

// AvailableSecondFactors implements userauth.SecondFactorProvider. Returns TOTP and/or email based on data presence.
func (stu *Users) AvailableSecondFactors(userID string) ([]userauth.SecondFactor, error) {
	for _, u := range stu.Users {
		if u.Id == userID {
			var factors []userauth.SecondFactor
			if u.TOTPSecret != "" {
				factors = append(factors, userauth.SecondFactorTOTP)
			}
			if u.Email2FA != "" {
				factors = append(factors, userauth.SecondFactorEmail)
			}
			return factors, nil
		}
	}
	return nil, nil
}

// VerifyRecoveryCode implements userauth.RecoveryCodeVerifier. Static users have no codes; always false.
func (stu *Users) VerifyRecoveryCode(userID, code string) (bool, error) {
	return false, nil
}

// FromFile loads a file containing user information and returns static user
// possible files are json, yaml and htpasswd
func FromFile(file string) (*Users, error) {
	fType := fileType(file)

	switch fType {
	case ExtYaml, ExtYml:
		b, err := os.ReadFile(file) //nolint: gosec // bytes are parsed as yaml Users struct
		if err != nil {
			return nil, err
		}
		return yamlBytes(b)
	case ExtJson:
		b, err := os.ReadFile(file) //nolint: gosec // bytes are parsed as json Users struct
		if err != nil {
			return nil, err
		}
		return jsonBytes(b)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}

}

// unmarshal a yaml containing users into a list of users
func yamlBytes(in []byte) (*Users, error) {
	data := Users{}
	err := yaml.Unmarshal(in, &data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

// unmarshal a json containing users into a list of users
func jsonBytes(in []byte) (*Users, error) {
	data := Users{}
	err := json.Unmarshal(in, &data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

const (
	ExtYaml = "YAML"
	ExtYml  = "YML"
	ExtJson = "JSON"
)

func fileType(fpath string) string {
	filename := filepath.Base(fpath)
	extension := strings.TrimPrefix(filepath.Ext(filename), ".")
	extension = strings.ToUpper(extension)
	switch extension {
	case ExtYaml:
		return ExtYaml
	case ExtJson:
		return ExtJson
	default:
		return ""
	}
}
