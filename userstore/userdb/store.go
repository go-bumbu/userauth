package userdb

import (
	"github.com/go-bumbu/userauth"
	"gorm.io/gorm"
)

// Ensure Store implements the interfaces it claims.
var (
	_ userauth.UserGetter           = (*Store)(nil)
	_ userauth.UserUpdater          = (*Store)(nil)
	_ userauth.SecondFactorProvider = (*Store)(nil)
)

// Store is an opinionated user manager that stores the information on a gorm database
type Store struct {
	db               *gorm.DB
	bcryptDifficulty int
	defaultEnabled   bool
	usernameFormat   userauth.UsernameFormat // validates login ID in Create (email, plain, or any)
	onDelete         []UserPurger            // satellite stores the user delete cascades into
}

type Opts struct {
	BcryptDifficulty int
	DefaultEnabled   bool                    // when true, users created via Create are enabled by default
	UsernameFormat   userauth.UsernameFormat // policy for login ID: email, plain, or any (default)
	// OnDelete are the satellite stores Delete cascades into, in order, once the
	// user row is gone. Anything holding rows keyed by user ID belongs here:
	// what the user store does not know about, it cannot clean up.
	OnDelete []UserPurger
}

// New creates an instance of the user store.
func New(db *gorm.DB, opts Opts) (*Store, error) {

	// Migrate the schema
	err := db.AutoMigrate(&userModel{}, &groupModel{}, &totpModel{}, &recoveryCodeModel{}, &emailVerificationCodeModel{}, &smsVerificationCodeModel{}, &secondFactorFlagsModel{}, &pendingEmailChangeModel{}, &patModel{})
	if err != nil {
		return nil, err
	}

	return &Store{
		db:               db,
		bcryptDifficulty: opts.BcryptDifficulty,
		defaultEnabled:   opts.DefaultEnabled,
		usernameFormat:   opts.UsernameFormat,
		onDelete:         opts.OnDelete,
	}, nil
}
