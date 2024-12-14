package authenticator

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
)

type AuthHandler interface {
	Name() string
	HandleAuth(w http.ResponseWriter, r *http.Request) (loggedIn, stopEvaluation bool)
}

type callback func(w http.ResponseWriter, r *http.Request)

type Authenticator struct {
	handlers             []AuthHandler
	Logger               *slog.Logger
	unauthorizedCallback callback
	authorizedCallback   callback
}

func New(handlers []AuthHandler, l *slog.Logger, unAuthCallback, authCallback callback) *Authenticator {
	logger := l
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	n := []string{}
	for _, h := range handlers {
		n = append(n, h.Name())
	}
	logger.Info("configuring authenticator", slog.String("handlers", strings.Join(n, ",")))

	a := Authenticator{
		handlers:             handlers,
		Logger:               logger,
		unauthorizedCallback: unAuthCallback,
		authorizedCallback:   authCallback,
	}
	return &a
}

func (a *Authenticator) EvalAuth(w http.ResponseWriter, r *http.Request) bool {

	for _, authHandler := range a.handlers {
		a.Logger.Debug("evaluating auth handler", slog.String("name", authHandler.Name()))
		ok, breakEval := authHandler.HandleAuth(w, r)
		a.Logger.Debug("auth handler result", slog.String("name", authHandler.Name()),
			slog.Bool("isAuthenticated", ok), slog.Bool("breakEvaluation", breakEval),
		)
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
		if a.EvalAuth(w, r) {
			next.ServeHTTP(w, r)

			if a.authorizedCallback != nil {
				a.authorizedCallback(w, r)
				return
			}
		} else {
			if a.unauthorizedCallback != nil {
				a.unauthorizedCallback(w, r)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}

	})
}
