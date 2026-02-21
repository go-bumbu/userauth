package cookieauth

import (
	"context"
	"fmt"
	"net/http"
)

type ctxKey string

// SessUserDataCtxKey is the context key for storing UserData on the request.
const SessUserDataCtxKey ctxKey = "sessionUserData"

// CtxGetUserData extracts and verifies the user information from a request context.
// The returned struct contains user information about the logged-in user.
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

// CtxSetUserData stores a copy of relevant user data in the request context.
func CtxSetUserData(r *http.Request, data SessionData) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, SessUserDataCtxKey, data.UserData)
	req := r.WithContext(ctx)
	*r = *req
}
