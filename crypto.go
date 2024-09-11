package userauth

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"slices"
	"strings"
)

const SHA1Prefix = "{SHA}"

// CheckPass compares a provided transient password (that is never stored) with the stored counterpart hash

func CheckPass(plainPass, hash string) (bool, error) {
	switch Alg(hash) {
	case Sha1:
		return checkSha1Pw(plainPass, hash)
	case Bcrypt:
		return checkBcryptPw(plainPass, hash)
	default:
		return false, fmt.Errorf("unknown crypto algorithm")
	}
}

func checkSha1Pw(plainPass, hash string) (bool, error) {
	b64hash := strings.TrimPrefix(hash, SHA1Prefix)
	hashed, err := base64.StdEncoding.DecodeString(b64hash)
	if err != nil {
		return false, fmt.Errorf("malformed sha1 hash: %s", err.Error())
	}
	if len(hashed) != sha1.Size {
		return false, fmt.Errorf("malformed sha1 wrong length")
	}
	st := sha1.Sum([]byte(plainPass))
	if subtle.ConstantTimeCompare(st[:], hashed) == 1 {
		return true, nil
	}
	return false, nil
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
	Sha1 = iota
	Bcrypt
	Unknown
)

func Alg(hash string) HashAlgo {
	if strings.HasPrefix(hash, SHA1Prefix) {
		return Sha1
	}
	if isbCryptString(hash) {
		return Bcrypt
	}
	return Unknown
}

func HashPw(pw string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(bytes), err
}
func MustHash(pw string) string {
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
