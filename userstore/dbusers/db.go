package dbusers

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/hashutil"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Ensure DbManager implements the split MFA interfaces.
var (
	_ userauth.TOTPConfigurator         = (*DbManager)(nil)
	_ userauth.RecoveryCodeConfigurator = (*DbManager)(nil)
	_ userauth.RecoveryCodeVerifier     = (*DbManager)(nil)
	_ userauth.RecoveryCodeCountGetter  = (*DbManager)(nil)
	_ userauth.UserUpdater              = (*DbManager)(nil)
)

// DbManager is an opinionated user manager that stores the information on a gorm database
type DbManager struct {
	db               *gorm.DB
	bcryptDifficulty int
	defaultEnabled   bool
	usernameFormat   userauth.UsernameFormat // validates login ID in Create (email, plain, or any)
	totpEncKey       []byte                  // AES-256 key for encrypting TOTP secrets at rest (nil = no encryption)
}

type ManagerOpts struct {
	BcryptDifficulty  int
	DefaultEnabled    bool                    // when true, users created via Create are enabled by default
	UsernameFormat    userauth.UsernameFormat // policy for login ID: email, plain, or any (default)
	TOTPEncryptionKey []byte                  // 32-byte AES-256 key for encrypting TOTP secrets; nil disables encryption
}

// NewDbManager creates an instance of user manager
func NewDbManager(db *gorm.DB, opts ManagerOpts) (*DbManager, error) {

	// Migrate the schema
	err := db.AutoMigrate(&userModel{}, &totpModel{}, &recoveryCodeModel{}, &emailVerificationCodeModel{}, &smsVerificationCodeModel{}, &secondFactorFlagsModel{}, &pendingEmailChangeModel{})
	if err != nil {
		return nil, err
	}

	if len(opts.TOTPEncryptionKey) != 0 && len(opts.TOTPEncryptionKey) != 32 {
		return nil, fmt.Errorf("TOTPEncryptionKey must be exactly 32 bytes, got %d", len(opts.TOTPEncryptionKey))
	}

	return &DbManager{
		db:               db,
		bcryptDifficulty: opts.BcryptDifficulty,
		defaultEnabled:   opts.DefaultEnabled,
		usernameFormat:   opts.UsernameFormat,
		totpEncKey:       opts.TOTPEncryptionKey,
	}, nil
}

// userModel is the database representation of the user. LoginID is the unique identifier.
type userModel struct {
	gorm.Model
	LoginID              string `gorm:"uniqueIndex;not null"` // login identifier (may or may not be an email)
	Name                 string
	Pw                   string
	Enabled              bool
	PrimaryEmail         string
	PrimaryEmailVerified bool
	BackupEmail          string
	BackupEmailVerified  bool
}

// totpModel stores TOTP secret and enabled flag per user (UserID = login ID).
type totpModel struct {
	gorm.Model
	UserID  string `gorm:"uniqueIndex;not null"`
	Secret  string `gorm:"not null"`
	Enabled bool
}

func (totpModel) TableName() string { return "user_totp" }

// recoveryCodeModel stores one recovery code hash per row (user_recovery_codes table).
type recoveryCodeModel struct {
	gorm.Model
	UserID   string `gorm:"index;not null"`
	CodeHash string `gorm:"not null"`
}

func (recoveryCodeModel) TableName() string { return "user_recovery_codes" }

// MaxRecoveryCodes is the maximum number of recovery codes allowed per user in SetRecoveryCodes.
const MaxRecoveryCodes = 6

// emailVerificationCodeModel stores one email verification code per user (user_email_verification_codes table).
// Replaced on each GenerateEmailVerificationCode.
type emailVerificationCodeModel struct {
	gorm.Model
	UserID    string    `gorm:"uniqueIndex;not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
}

func (emailVerificationCodeModel) TableName() string { return "user_email_verification_codes" }

// smsVerificationCodeModel stores one SMS verification code per user (user_sms_verification_codes table).
type smsVerificationCodeModel struct {
	gorm.Model
	UserID    string    `gorm:"uniqueIndex;not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
}

func (smsVerificationCodeModel) TableName() string { return "user_sms_verification_codes" }

// secondFactorFlagsModel stores per-user flags for email/SMS 2FA (user_second_factor_flags table).
type secondFactorFlagsModel struct {
	gorm.Model
	UserID       string `gorm:"uniqueIndex;not null"`
	EmailEnabled bool
	SMSEnabled   bool
}

func (secondFactorFlagsModel) TableName() string { return "user_second_factor_flags" }

// pendingEmailChangeModel stores a pending email change awaiting code verification.
type pendingEmailChangeModel struct {
	gorm.Model
	UserID    string    `gorm:"uniqueIndex;not null"`
	NewEmail  string    `gorm:"not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
}

func (pendingEmailChangeModel) TableName() string { return "user_pending_email_changes" }

// User is the input struct for CreateUser (login ID and optional email fields).
type User struct {
	Name                 string `yaml:"name"`
	LoginID              string `yaml:"login_id"` // unique login identifier (required)
	Pw                   string `yaml:"pw"`
	Enabled              bool   `yaml:"enabled"`
	PrimaryEmail         string `yaml:"primary_email"`
	PrimaryEmailVerified bool   `yaml:"primary_email_verified"`
	BackupEmail          string `yaml:"backup_email"`
	BackupEmailVerified  bool   `yaml:"backup_email_verified"`
}

func (mng DbManager) Create(id string, pw string) error {
	if err := userauth.ValidateLoginID(id, mng.usernameFormat); err != nil {
		return err
	}
	usr := User{
		LoginID: id,
		Pw:      pw,
		Enabled: mng.defaultEnabled,
	}
	return mng.CreateUser(usr)
}

func (mng DbManager) CreateUser(usr User) error {
	if usr.LoginID == "" {
		return errors.New("login ID cannot be empty")
	}
	if usr.Pw == "" {
		return errors.New("password cannot be empty")
	}

	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(usr.Pw), mng.bcryptDifficulty)
	if err != nil {
		return err
	}

	usrModel := userModel{
		Name:                 usr.Name,
		LoginID:              usr.LoginID,
		Pw:                   string(hashedPasswd),
		Enabled:              usr.Enabled,
		PrimaryEmail:         usr.PrimaryEmail,
		PrimaryEmailVerified: usr.PrimaryEmailVerified,
		BackupEmail:          usr.BackupEmail,
		BackupEmailVerified:  usr.BackupEmailVerified,
	}

	return mng.db.Create(&usrModel).Error
}

// CreateUserWithHashedPassword creates a user with a pre-hashed password.
// Unlike CreateUser, this does not hash the password - it stores it directly.
// Use this when provisioning users with passwords that are already bcrypt hashed.
func (mng DbManager) CreateUserWithHashedPassword(usr User) error {
	if usr.LoginID == "" {
		return errors.New("login ID cannot be empty")
	}
	if usr.Pw == "" {
		return errors.New("password cannot be empty")
	}

	usrModel := userModel{
		Name:                 usr.Name,
		LoginID:              usr.LoginID,
		Pw:                   usr.Pw,
		Enabled:              usr.Enabled,
		PrimaryEmail:         usr.PrimaryEmail,
		PrimaryEmailVerified: usr.PrimaryEmailVerified,
		BackupEmail:          usr.BackupEmail,
		BackupEmailVerified:  usr.BackupEmailVerified,
	}

	return mng.db.Create(&usrModel).Error
}

// GetUser implements userauth.UserGetter. Looks up user by login ID.
func (mng DbManager) GetUser(id string) (userauth.User, error) {
	var m userModel
	err := mng.db.First(&m, "login_id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.User{}, userauth.ErrUserNotFound
		}
		return userauth.User{}, err
	}
	return userauth.User{
		Id:                   m.LoginID,
		HashPw:               m.Pw,
		Enabled:              m.Enabled,
		PrimaryEmail:         m.PrimaryEmail,
		PrimaryEmailVerified: m.PrimaryEmailVerified,
		BackupEmail:          m.BackupEmail,
		BackupEmailVerified:  m.BackupEmailVerified,
	}, nil
}

// GetTOTP implements userauth.TOTPGetter. Decrypts the secret if an encryption key is configured.
func (mng DbManager) GetTOTP(userID string) (userauth.TOTPData, error) {
	var m totpModel
	err := mng.db.First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.TOTPData{Enabled: false}, nil
		}
		return userauth.TOTPData{}, err
	}
	secret := m.Secret
	if mng.totpEncKey != nil && secret != "" {
		decrypted, err := hashutil.Decrypt(secret, mng.totpEncKey)
		if err != nil {
			return userauth.TOTPData{}, fmt.Errorf("decrypt TOTP secret: %w", err)
		}
		secret = decrypted
	}
	return userauth.TOTPData{
		Enabled: m.Enabled,
		Secret:  secret,
	}, nil
}

// SetTOTP is a store method for configuring TOTP. Encrypts the secret if an encryption key is configured.
func (mng DbManager) SetTOTP(userID string, data userauth.TOTPData) error {
	var m totpModel
	err := mng.db.First(&m, "user_id = ?", userID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	secret := data.Secret
	if mng.totpEncKey != nil && secret != "" {
		encrypted, encErr := hashutil.Encrypt(secret, mng.totpEncKey)
		if encErr != nil {
			return fmt.Errorf("encrypt TOTP secret: %w", encErr)
		}
		secret = encrypted
	}
	m.UserID = userID
	m.Secret = secret
	m.Enabled = data.Enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mng.db.Create(&m).Error
	}
	return mng.db.Save(&m).Error
}

// SetRecoveryCodes is a store method. Replaces all codes for the user. Accepts at most MaxRecoveryCodes.
// Delete and inserts run in a single transaction.
func (mng DbManager) SetRecoveryCodes(userID string, hashedCodes []string) error {
	if len(hashedCodes) > MaxRecoveryCodes {
		return fmt.Errorf("recovery codes: at most %d allowed, got %d", MaxRecoveryCodes, len(hashedCodes))
	}
	return mng.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&recoveryCodeModel{}).Error; err != nil {
			return err
		}
		for _, h := range hashedCodes {
			if h == "" {
				continue
			}
			if err := tx.Create(&recoveryCodeModel{UserID: userID, CodeHash: h}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// VerifyRecoveryCode implements userauth.RecoveryCodeVerifier. Consumes the code on success.
// Loads all stored bcrypt hashes for the user and compares against each (max 6 codes).
func (mng DbManager) VerifyRecoveryCode(userID, code string) (bool, error) {
	var codes []recoveryCodeModel
	err := mng.db.Where("user_id = ?", userID).Find(&codes).Error
	if err != nil {
		return false, err
	}
	for _, m := range codes {
		if hashutil.VerifyRecoveryCodeHash(code, m.CodeHash) {
			if err := mng.db.Delete(&m).Error; err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// GetRecoveryCodesCount is a store method.
func (mng DbManager) GetRecoveryCodesCount(userID string) (int, error) {
	var count int64
	err := mng.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).Count(&count).Error
	return int(count), err
}

// StoreEmailCode persists a hashed email verification code, replacing any existing code for the user.
func (mng DbManager) StoreEmailCode(userID, codeHash string, expiresAt time.Time) error {
	if err := mng.db.Where("user_id = ?", userID).Delete(&emailVerificationCodeModel{}).Error; err != nil {
		return err
	}
	return mng.db.Create(&emailVerificationCodeModel{UserID: userID, CodeHash: codeHash, ExpiresAt: expiresAt}).Error
}

// AvailableSecondFactors implements userauth.SecondFactorProvider.
func (mng DbManager) AvailableSecondFactors(userID string) ([]userauth.SecondFactor, error) {
	var out []userauth.SecondFactor
	totpData, err := mng.GetTOTP(userID)
	if err != nil {
		return nil, err
	}
	if totpData.Enabled {
		out = append(out, userauth.SecondFactorTOTP)
	}
	emailEnabled, err := mng.emailCodeEnabled(userID)
	if err != nil {
		return nil, err
	}
	if emailEnabled {
		out = append(out, userauth.SecondFactorEmail)
	}
	smsEnabled, err := mng.smsCodeEnabled(userID)
	if err != nil {
		return nil, err
	}
	if smsEnabled {
		out = append(out, userauth.SecondFactorSMS)
	}
	return out, nil
}

// emailCodeEnabled returns whether email 2FA is enabled for the user (used by AvailableSecondFactors).
func (mng DbManager) emailCodeEnabled(userID string) (bool, error) {
	var f secondFactorFlagsModel
	err := mng.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return f.EmailEnabled, nil
}

// SetEmailCodeEnabled is a store method to enable or disable email 2FA for a user.
func (mng DbManager) SetEmailCodeEnabled(userID string, enabled bool) error {
	var f secondFactorFlagsModel
	err := mng.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	f.UserID = userID
	f.EmailEnabled = enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mng.db.Create(&f).Error
	}
	return mng.db.Save(&f).Error
}

// VerifyEmailCode implements userauth.EmailCodeVerifier. Consumes the code on success if not expired.
func (mng DbManager) VerifyEmailCode(userID, code string) (bool, error) {
	hash := hashutil.HashCodeSHA256(code)
	var m emailVerificationCodeModel
	err := mng.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = mng.db.Delete(&m).Error
		return false, nil
	}
	if err := mng.db.Delete(&m).Error; err != nil {
		return false, err
	}
	return true, nil
}

// StoreSMSCode persists a hashed SMS verification code, replacing any existing code for the user.
func (mng DbManager) StoreSMSCode(userID, codeHash string, expiresAt time.Time) error {
	if err := mng.db.Where("user_id = ?", userID).Delete(&smsVerificationCodeModel{}).Error; err != nil {
		return err
	}
	return mng.db.Create(&smsVerificationCodeModel{UserID: userID, CodeHash: codeHash, ExpiresAt: expiresAt}).Error
}

// smsCodeEnabled returns whether SMS 2FA is enabled for the user (used by AvailableSecondFactors).
func (mng DbManager) smsCodeEnabled(userID string) (bool, error) {
	var f secondFactorFlagsModel
	err := mng.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return f.SMSEnabled, nil
}

// SetSMSCodeEnabled is a store method to enable or disable SMS 2FA for a user.
func (mng DbManager) SetSMSCodeEnabled(userID string, enabled bool) error {
	var f secondFactorFlagsModel
	err := mng.db.Where("user_id = ?", userID).First(&f).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	f.UserID = userID
	f.SMSEnabled = enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mng.db.Create(&f).Error
	}
	return mng.db.Save(&f).Error
}

// VerifySMSCode implements userauth.SMSCodeVerifier. Consumes the code on success if not expired.
func (mng DbManager) VerifySMSCode(userID, code string) (bool, error) {
	hash := hashutil.HashCodeSHA256(code)
	var m smsVerificationCodeModel
	err := mng.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = mng.db.Delete(&m).Error
		return false, nil
	}
	if err := mng.db.Delete(&m).Error; err != nil {
		return false, err
	}
	return true, nil
}

// SetPrimaryEmail updates the primary email for a user. Resets PrimaryEmailVerified to false.
func (mng DbManager) SetPrimaryEmail(userID, email string) error {
	return mng.db.Model(&userModel{}).Where("login_id = ?", userID).
		Updates(map[string]interface{}{
			"primary_email":          email,
			"primary_email_verified": false,
		}).Error
}

// SetPrimaryEmailVerified sets the primary email verified flag for a user.
func (mng DbManager) SetPrimaryEmailVerified(userID string, verified bool) error {
	return mng.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("primary_email_verified", verified).Error
}

// SetEnabled sets the enabled flag for a user.
func (mng DbManager) SetEnabled(userID string, enabled bool) error {
	return mng.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("enabled", enabled).Error
}

// SetPasswordHash updates the password hash for an existing user.
// The hash should be a valid bcrypt hash. This method does not hash the input.
func (mng DbManager) SetPasswordHash(userID, hashedPw string) error {
	return mng.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("pw", hashedPw).Error
}

// StorePendingEmailChange stores a pending email change, replacing any existing one for the user.
func (mng DbManager) StorePendingEmailChange(userID, newEmail, codeHash string, expiresAt time.Time) error {
	if err := mng.db.Where("user_id = ?", userID).Delete(&pendingEmailChangeModel{}).Error; err != nil {
		return err
	}
	return mng.db.Create(&pendingEmailChangeModel{
		UserID:    userID,
		NewEmail:  newEmail,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
	}).Error
}

// GetPendingEmailChange returns the pending email change for a user, if any and not expired.
func (mng DbManager) GetPendingEmailChange(userID string) (newEmail string, err error) {
	var m pendingEmailChangeModel
	err = mng.db.Where("user_id = ?", userID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("no pending email change")
		}
		return "", err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = mng.db.Delete(&m).Error
		return "", fmt.Errorf("pending email change expired")
	}
	return m.NewEmail, nil
}

// VerifyPendingEmailChange verifies the code for a pending email change and returns the new email.
// Consumes the pending change on success.
func (mng DbManager) VerifyPendingEmailChange(userID, code string) (newEmail string, err error) {
	hash := hashutil.HashCodeSHA256(code)
	var m pendingEmailChangeModel
	err = mng.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("invalid code")
		}
		return "", err
	}
	if time.Now().UTC().After(m.ExpiresAt) {
		_ = mng.db.Delete(&m).Error
		return "", fmt.Errorf("code expired")
	}
	if err := mng.db.Delete(&m).Error; err != nil {
		return "", err
	}
	return m.NewEmail, nil
}
