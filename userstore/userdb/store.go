package userdb

import (
	"fmt"

	"github.com/go-bumbu/userauth"
	"gorm.io/gorm"
)

// Ensure Store implements the split MFA interfaces.
var (
	_ userauth.TOTPConfigurator         = (*Store)(nil)
	_ userauth.RecoveryCodeConfigurator = (*Store)(nil)
	_ userauth.RecoveryCodeVerifier     = (*Store)(nil)
	_ userauth.RecoveryCodeCountGetter  = (*Store)(nil)
	_ userauth.UserUpdater              = (*Store)(nil)
)

// Store is an opinionated user manager that stores the information on a gorm database
type Store struct {
	db               *gorm.DB
	bcryptDifficulty int
	defaultEnabled   bool
	usernameFormat   userauth.UsernameFormat // validates login ID in Create (email, plain, or any)
	totpEncKey       []byte                  // AES-256 key for encrypting TOTP secrets at rest (nil = no encryption)
}

type Opts struct {
	BcryptDifficulty  int
	DefaultEnabled    bool                    // when true, users created via Create are enabled by default
	UsernameFormat    userauth.UsernameFormat // policy for login ID: email, plain, or any (default)
	TOTPEncryptionKey []byte                  // 32-byte AES-256 key for encrypting TOTP secrets; nil disables encryption
}

// New creates an instance of the user store.
func New(db *gorm.DB, opts Opts) (*Store, error) {

	// Migrate the schema
	err := db.AutoMigrate(&userModel{}, &groupModel{}, &totpModel{}, &recoveryCodeModel{}, &emailVerificationCodeModel{}, &smsVerificationCodeModel{}, &secondFactorFlagsModel{}, &pendingEmailChangeModel{})
	if err != nil {
		return nil, err
	}

	if len(opts.TOTPEncryptionKey) != 0 && len(opts.TOTPEncryptionKey) != 32 {
		return nil, fmt.Errorf("TOTPEncryptionKey must be exactly 32 bytes, got %d", len(opts.TOTPEncryptionKey))
	}

	return &Store{
		db:               db,
		bcryptDifficulty: opts.BcryptDifficulty,
		defaultEnabled:   opts.DefaultEnabled,
		usernameFormat:   opts.UsernameFormat,
		totpEncKey:       opts.TOTPEncryptionKey,
	}, nil
}
