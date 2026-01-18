package sessionauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-bumbu/userauth"
	"net/http"
)

const SessionMngrName = "sessionAuth"

func (sMngr *Manager) Name() string {
	return SessionMngrName
}

// HandleAuth implements the authenticator.AuthHandler interface to allow to use session based in the authenticator
func (sMngr *Manager) HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool) {
	stopEvaluation = false
	allowAccess = false

	data, session, err := sMngr.read(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if data.IsAuthenticated {
		allowAccess = true
		CtxSetUserData(r, data)
		err = sMngr.updateExpiry(data, session, r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	return
}

// middleware ------------------------------------------------------------

// Middleware is a simple session auth middleware that will only allow access if the user is logged in
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func (sMngr *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canLogin, _ := sMngr.HandleAuth(w, r)
		if canLogin {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func (sMngr *Manager) LogoutHandler(redirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := sMngr.LogoutUser(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	})
}

// Form based auth handler  ------------------------------------------------------------

// FormAuthHandler is a simple session auth handler that will respond to a form POST request and login a user
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func (sMngr *Manager) FormAuthHandler(auth userauth.LoginHandler, redirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusInternalServerError)
			return
		}

		userName := r.FormValue("username")
		userPw := r.FormValue("password")

		// handle "keep me logged in"
		sessRen := false
		sessionRenew := r.FormValue("session_renew")
		if sessionRenew == "on" {
			sessRen = true
		}

		canLogin, err := auth.CanLogin(userName, userPw)
		if err != nil {
			// only return an error if it's NOT user not found or user disabled
			switch {
			case errors.Is(err, userauth.ErrUserNotFound):
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				//http.Error(w, "User not found", http.StatusUnauthorized)
				return
			case errors.Is(err, userauth.ErrUserDisabled):
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				//http.Error(w, "User is disabled", http.StatusUnauthorized)
				return
			default:
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if canLogin {
			err = sMngr.LoginUser(r, w, userName, sessRen)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			sMngr.logger.Debug("login successful", "username", userName)
		} else {
			//http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			sMngr.logger.Debug("login unsuccessful", "username", userName)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	})
}

// Json POST basd auth handler  ------------------------------------------------------------

type loginData struct {
	User           string `json:"username"`
	Pw             string `json:"password"`
	KeepMeLoggedIn bool   `json:"sessionRenew"`
	Redirect       string
}

// JsonAuthHandler is a simple session auth handler that will respond to a Json POST request and login a user
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func (sMngr *Manager) JsonAuthHandler(auth userauth.LoginHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload loginData

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if payload.User == "" || payload.Pw == "" {
			http.Error(w, "User or Password cannot be empty", http.StatusBadRequest)
			return
		}

		canLogin, err := auth.CanLogin(payload.User, payload.Pw)
		if err != nil {
			// only return an error if it's NOT user not found or user disabled
			switch {
			case errors.Is(err, userauth.ErrUserNotFound):
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			case errors.Is(err, userauth.ErrUserDisabled):
				http.Error(w, "User is disabled", http.StatusUnauthorized)
				return
			default:
				http.Error(w, fmt.Sprintf("Error while checking user login: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if canLogin {
			err = sMngr.LoginUser(r, w, payload.User, payload.KeepMeLoggedIn)
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
