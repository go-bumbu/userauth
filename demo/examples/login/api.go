package login

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	flowmemory "github.com/go-bumbu/userauth/flow/login/attemptstore/memory"
	loginhandlers "github.com/go-bumbu/userauth/flow/login/handlers"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/securecookie"
)

// API exposes password+TOTP login as a JSON API using the login/handlers
// preset — the transport SPAs would consume. Password-only users complete at
// the login endpoint; users with TOTP enrolled (e.g. via /profile) get
// {"done":false,"next":["totp","recovery"]} and complete at the verify
// endpoint. The demo mounts LoginHandler and VerifyHandler on the router.
func API(log *slog.Logger, users *userdb.Store, mfaSvc mfa.Services) *loginhandlers.JSON {
	sesStore, err := cookieauth.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
	if err != nil {
		panic(fmt.Errorf("login api: cookie store: %w", err))
	}
	sessMgr, err := cookieauth.New(cookieauth.Cfg{
		Store:         sesStore,
		CookieName:    "_api_login_auth",
		AllowRenew:    true,
		SessionDur:    0,
		MaxSessionDur: 0,
		MinWriteSpace: 120 * time.Second,
		Logger:        log,
	})
	if err != nil {
		panic(fmt.Errorf("login api: session manager: %w", err))
	}

	return loginhandlers.NewPasswordTOTP(loginhandlers.PasswordTOTPCfg{
		Users:    users,
		Session:  sessMgr,
		Attempts: flowmemory.New(),
		TOTP:     mfaSvc.TOTP,
		Recovery: mfaSvc.Recovery,
		Logger:   log,
	})
}
