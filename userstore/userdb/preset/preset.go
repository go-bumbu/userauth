// Package preset wires the full GORM setup in one call: the user store plus
// every satellite store, over one database handle, with the user-delete cascade
// and the second-factor provider already connected.
//
// It is a separate package on purpose. userstore/userdb must not import the
// factor services — that decoupling is what lets a caller create two tables
// instead of nine — so the convenience constructor lives one level out, where
// importing everything is the whole point.
//
// Reach for it when you want the library's full feature set on a database. When
// you want a subset, construct the stores you need directly and skip this
// package: what you never construct never creates a table.
package preset

import (
	"fmt"

	"github.com/go-bumbu/userauth"
	patdb "github.com/go-bumbu/userauth/service/pat/store/db"
	recoverydb "github.com/go-bumbu/userauth/service/recoverycodes/store/db"
	"github.com/go-bumbu/userauth/service/secondfactor"
	flagsdb "github.com/go-bumbu/userauth/service/secondfactor/store/db"
	totpdb "github.com/go-bumbu/userauth/service/totp/store/db"
	codedb "github.com/go-bumbu/userauth/service/verificationcode/store/db"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"gorm.io/gorm"
)

// Channel labels for the two verification-code stores Full creates. They are
// part of the row key, so changing them orphans outstanding codes.
const (
	ChannelEmail = "email"
	ChannelSMS   = "sms"
)

// Stores is every GORM store of the full setup, already wired together. The
// concrete types are exposed rather than the service interfaces: a caller needs
// the concrete store to hand to its service constructor, and hiding it behind
// the interface would only force a type assertion back.
type Stores struct {
	Users      *userdb.Store
	TOTP       *totpdb.Store
	Recovery   *recoverydb.Store
	PATs       *patdb.Store
	EmailCodes *codedb.Store
	SMSCodes   *codedb.Store
	Flags      *flagsdb.Store
	// Provider answers userauth.SecondFactorProvider over the stores above:
	// TOTP from a confirmed enrolment, email and SMS from the stored flags.
	Provider secondfactor.Provider
}

// Full constructs the user store and every satellite store over db, migrating
// each table, and registers the satellites as the user store's delete cascade.
//
// The satellites are built first so the user store can register them as purgers.
func Full(db *gorm.DB, opts userdb.Opts) (Stores, error) {
	totpStore, err := totpdb.New(db)
	if err != nil {
		return Stores{}, fmt.Errorf("create totp store: %w", err)
	}
	recoveryStore, err := recoverydb.New(db)
	if err != nil {
		return Stores{}, fmt.Errorf("create recovery code store: %w", err)
	}
	patStore, err := patdb.New(db)
	if err != nil {
		return Stores{}, fmt.Errorf("create pat store: %w", err)
	}
	emailCodes, err := codedb.New(db, ChannelEmail)
	if err != nil {
		return Stores{}, fmt.Errorf("create email code store: %w", err)
	}
	smsCodes, err := codedb.New(db, ChannelSMS)
	if err != nil {
		return Stores{}, fmt.Errorf("create sms code store: %w", err)
	}
	flagStore, err := flagsdb.New(db)
	if err != nil {
		return Stores{}, fmt.Errorf("create second factor flag store: %w", err)
	}

	// one code store purges every channel, so listing both would delete twice
	opts.OnDelete = append(opts.OnDelete,
		totpStore, recoveryStore, patStore, emailCodes, flagStore,
	)

	users, err := userdb.New(db, opts)
	if err != nil {
		return Stores{}, fmt.Errorf("create user store: %w", err)
	}

	return Stores{
		Users:      users,
		TOTP:       totpStore,
		Recovery:   recoveryStore,
		PATs:       patStore,
		EmailCodes: emailCodes,
		SMSCodes:   smsCodes,
		Flags:      flagStore,
		Provider: secondfactor.Provider{
			TOTP:  totpStore,
			Email: secondfactor.Flag{Store: flagStore, Factor: userauth.SecondFactorEmail},
			SMS:   secondfactor.Flag{Store: flagStore, Factor: userauth.SecondFactorSMS},
		},
	}, nil
}
