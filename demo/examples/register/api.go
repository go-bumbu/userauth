package register

import (
	"log/slog"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/internal/deliver"
	registerhandlers "github.com/go-bumbu/userauth/flow/register/handlers"
	pendingmemory "github.com/go-bumbu/userauth/flow/register/pendingstore/memory"
	"github.com/go-bumbu/userauth/service/verificationcode"
	csmemory "github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/userstore/userdb"
)

// NewAPI exposes the same email-verified registration as a JSON API using
// the register/handlers preset — the transport SPAs would consume. The demo
// cannot send email, so the deliverer logs the code to the server console
// instead.
func NewAPI(log *slog.Logger, users *userdb.Store) *registerhandlers.JSON {
	return registerhandlers.New(registerhandlers.Cfg{
		Users:   users,
		Creator: userdbCreator{users: users},
		Pending: pendingmemory.New(),
		Codes: verificationcode.NewService(csmemory.New(), verificationcode.Opts{
			CodeLength: 6,
			Expiry:     10 * time.Minute,
		}),
		// a real deployment would wire deliver/smtp instead
		Deliver:        deliver.Log{Logger: log, Msg: "register api: verification code issued"},
		UsernameFormat: userauth.UsernameFormatEmail,
		Logger:         log,
	})
}
