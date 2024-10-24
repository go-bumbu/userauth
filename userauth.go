package userauth

import (
	"errors"
)

//type UserLogin interface {
//	CanLogin(user string, password string) bool
//}
//type UserLoginTotp interface {
//	CanLogin(user string, password string) bool
//	CheckTopt(user string, topt string) bool
//}

type User struct {
	Id      string // user Identifying string: e.g. name or email
	HashPw  string // hashed passwd in one of the supported algorithms
	Enabled bool   // flag if user is enabled
}

type UserStore interface {
	GetUser(id string) (User, error)
}

type LoginHandler struct {
	UserStore UserStore
}

func (lh LoginHandler) CanLogin(userId string, plainPw string) (bool, error) {
	user, err := lh.UserStore.GetUser(userId)

	if errors.Is(err, NotFoundErr) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	if !user.Enabled {
		return false, UserDisabledErr
	}
	isOk, err := CheckPass(plainPw, user.HashPw)
	if err != nil {
		return false, err
	}
	return isOk, nil
}

// NotFoundErr is thrown when a user is not found
var NotFoundErr = errors.New("user not found")

// UserDisabledErr is thrown when a user is not enabled
var UserDisabledErr = errors.New("user is not enabled")
