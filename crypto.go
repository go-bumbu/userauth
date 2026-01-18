package userauth

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"slices"
	"strings"
)

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
