package sessionauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-bumbu/userauth"
	"net/http"
)

// Auth middleware ------------------------------------------------------------

const UserIdKey = "loggedInUserID"
const UserIsLoggedInKey = "isUserLoggedIn"

// Middleware is a simple session auth middleware that will only allow access if the user is logged in
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func (auth *AuthMngr) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := auth.ReadUpdate(r, w)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if data.IsAuthenticated {
			// add user ID into request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIdKey, data.UserId)
			ctx = context.WithValue(ctx, UserIsLoggedInKey, true)

			req := r.WithContext(ctx)
			*r = *req

			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// Form based auth handler  ------------------------------------------------------------

// FormAuthHandler is a simple session auth handler that will respond to a form POST request and login a user
// this can be used as simple implementations or as inspiration to customize an authentication middleware
func FormAuthHandler(session *AuthMngr, user userauth.UserLogin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		err = r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusInternalServerError)
			return
		}

		userName := r.FormValue("user")
		userPw := r.FormValue("pw")

		if user.CanLogin(userName, userPw) {
			err = session.Login(r, w, userName)
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
func JsonAuthHandler(session *AuthMngr, user userauth.UserLogin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload loginData

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if user.CanLogin(payload.User, payload.Pw) {
			err = session.Login(r, w, payload.User)
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

// CtxCheckAuth extracts and verifies the user information from a request context
// the returned struct contains user information about the logged-in user
func CtxCheckAuth(r *http.Request) (UserData, error) {

	var d UserData
	ctx := r.Context()

	val := ctx.Value(UserIsLoggedInKey)
	isLoggedIn, ok := val.(bool)
	if !ok || (ok && !isLoggedIn) {
		return d, ErrorUnauthorized{missingData: "isLoggedIn"}
	}

	val = ctx.Value(UserIdKey)
	userId, ok := val.(string)
	if !ok || (ok && userId == "") {
		return d, ErrorUnauthorized{missingData: "userId"}
	}

	d = UserData{
		UserId:          userId,
		IsAuthenticated: isLoggedIn,
	}
	return d, nil
}

type ErrorUnauthorized struct {
	missingData string
}

func (r ErrorUnauthorized) Error() string {
	return fmt.Sprintf("user login information not provided in request context: %s", r.missingData)
}
