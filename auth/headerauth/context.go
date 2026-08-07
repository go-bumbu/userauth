package headerauth

import (
	"context"
	"fmt"
	"net/http"
)

type ctxKey string

// RequestDataCtxKey is the context key for storing RequestData on the request.
const RequestDataCtxKey ctxKey = "headerAuthRequestData"

// CtxGetRequestData extracts the proxy-asserted identity from a request
// context. It only yields data after HandleAuth authenticated the request.
func CtxGetRequestData(r *http.Request) (RequestData, error) {
	val := r.Context().Value(RequestDataCtxKey)
	data, ok := val.(RequestData)
	if !ok {
		return data, fmt.Errorf("unable to obtain header auth data from context")
	}
	if data.UserName == "" {
		return data, fmt.Errorf("username in context is empty")
	}
	return data, nil
}

// CtxSetRequestData stores the proxy-asserted identity in the request context.
func CtxSetRequestData(r *http.Request, data RequestData) {
	ctx := context.WithValue(r.Context(), RequestDataCtxKey, data)
	*r = *r.WithContext(ctx)
}
