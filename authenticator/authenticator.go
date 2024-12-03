package authenticator

import (
	"log/slog"
	"net/http"
)

type AuthHandler interface {
	Name() string
	HandleAuth(w http.ResponseWriter, r *http.Request) (loggedIn, stopEvaluation bool)
}

type Authenticator struct {
	handlers             []AuthHandler
	Logger               *slog.Logger
	UnauthorizedCallback func(w http.ResponseWriter, r *http.Request)
}

func New() *Authenticator {
	a := Authenticator{
		handlers: []AuthHandler{},
		Logger:   nil,
	}
	return &a
}

func (a *Authenticator) Add(h AuthHandler) {
	a.handlers = append(a.handlers, h)
}

func (a *Authenticator) Evaluate(w http.ResponseWriter, r *http.Request) bool {
	for _, authHandler := range a.handlers {
		ok, breakEval := authHandler.HandleAuth(w, r)
		if ok {
			return true
		}
		if breakEval {
			break
		}
	}
	return false
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Evaluate(w, r) {
			next.ServeHTTP(w, r)
		}
		if a.UnauthorizedCallback != nil {
			a.UnauthorizedCallback(w, r)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
