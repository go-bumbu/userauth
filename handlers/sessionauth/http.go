package sessionauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-bumbu/userauth"
	"net/http"
)

// Manager middleware ------------------------------------------------------------

// Middleware is a simple session auth middleware that will only allow access if the user is logged in
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func (sMngr *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := sMngr.Read(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if data.IsAuthenticated {
			CtxSetUserData(r, data)
			next.ServeHTTP(w, r)

			err = sMngr.UpdateExpiry(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// Form based auth handler  ------------------------------------------------------------

// FormAuthHandler is a simple session auth handler that will respond to a form POST request and login a user
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func FormAuthHandler(sMngr *Manager, auth userauth.LoginHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusInternalServerError)
			return
		}

		userName := r.FormValue("user")
		userPw := r.FormValue("password")

		canLogin, err := auth.CanLogin(userName, userPw)
		if err != nil {
			// only return an error if it's NOT user not found or user disabled
			switch {
			case errors.Is(err, userauth.NotFoundErr):
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			case errors.Is(err, userauth.UserDisabledErr):
				http.Error(w, "User is disabled", http.StatusUnauthorized)
				return
			default:
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if canLogin {
			err = sMngr.LoginUser(r, w, userName)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

// Json POST basd auth handler  ------------------------------------------------------------

type loginData struct {
	User     string `json:"user"`
	Pw       string `json:"password"`
	Redirect string
}

// JsonAuthHandler is a simple session auth handler that will respond to a Json POST request and login a user
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func JsonAuthHandler(sMngr *Manager, auth userauth.LoginHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload loginData

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		canLogin, err := auth.CanLogin(payload.User, payload.Pw)
		if err != nil {
			// only return an error if it's NOT user not found or user disabled
			switch {
			case errors.Is(err, userauth.NotFoundErr):
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			case errors.Is(err, userauth.UserDisabledErr):
				http.Error(w, "User is disabled", http.StatusUnauthorized)
				return
			default:
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if canLogin {
			err = sMngr.LoginUser(r, w, payload.User)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

// request context  ------------------------------------------------------------

type ctxKey string

const SessUserDataCtxKey ctxKey = "sessionUserData"

// CtxGetUserData extracts and verifies the user information from a request context
// the returned struct contains user information about the logged-in user
func CtxGetUserData(r *http.Request) (UserData, error) {
	ctx := r.Context()

	val := ctx.Value(SessUserDataCtxKey)
	udata, ok := val.(UserData)
	if !ok {
		return udata, fmt.Errorf("unable to obtain user data from context")
	}

	if udata.UserId == "" {
		return udata, fmt.Errorf("userid in context is empty")
	}

	return udata, nil
}

// CtxSetUserData will store a copy of relevant user data in the request context
func CtxSetUserData(r *http.Request, data SessionData) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, SessUserDataCtxKey, data.UserData)
	req := r.WithContext(ctx)
	*r = *req
}
