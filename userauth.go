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

func (lh LoginHandler) CanLogin(userId string, plainPw string) bool {
	user, err := lh.UserStore.GetUser(userId)

	var notFound *NotFoundErr
	if errors.As(err, &notFound) {
		return false
	} else if err != nil {
		// TODO handle error
	}

	if !user.Enabled {
		return false
	}
	isOk, err := CheckPass(plainPw, user.HashPw)
	if err != nil {
		return false
	}
	return isOk
}

// NotFoundErr is thrown when a user is not found
type NotFoundErr struct{}

func (e NotFoundErr) Error() string {
	return "user not found"
}
