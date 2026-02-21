package dbusers

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/hashutil"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// DbManager is an opinionated user manager that stores the information on a gorm database
type DbManager struct {
	db               *gorm.DB
	bcryptDifficulty int // exposed as parameter for make tests faster
	defaultEnabled   bool
}

type ManagerOpts struct {
	BcryptDifficulty int
	DefaultEnabled   bool // when true, users created via Create are enabled by default
}

// NewDbManager creates an instance of user manager
func NewDbManager(db *gorm.DB, opts ManagerOpts) (*DbManager, error) {

	// Migrate the schema
	err := db.AutoMigrate(&userModel{}, &totpModel{}, &recoveryCodeModel{}, &emailVerificationCodeModel{}, &smsVerificationCodeModel{}, &secondFactorFlagsModel{})
	if err != nil {
		return nil, err
	}

	return &DbManager{
		db:               db,
		bcryptDifficulty: opts.BcryptDifficulty, // set the cost of the difficulty
		defaultEnabled:   opts.DefaultEnabled,
	}, nil
}

// userModel is the database representation of the user
type userModel struct {
	gorm.Model
	Email   string `gorm:"uniqueIndex"`
	Name    string
	Pw      string
	Enabled bool
	// last login
	// login location
}

// totpModel stores TOTP secret and enabled flag per user (UserID = email).
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

// DefaultEmailCodeExpiry is the default lifetime of an email verification code.
const DefaultEmailCodeExpiry = 15 * time.Minute

// DefaultEmailCodeLength is the number of digits in the generated code.
const DefaultEmailCodeLength = 6

// DefaultSMSCodeExpiry is the default lifetime of an SMS verification code.
const DefaultSMSCodeExpiry = 10 * time.Minute

// DefaultSMSCodeLength is the number of digits in the generated SMS code.
const DefaultSMSCodeLength = 6

type User struct {
	Name    string `yaml:"name"`
	Email   string `yaml:"email"`
	Pw      string `yaml:"pw"` // or hashed passwd
	Enabled bool   `yaml:"enabled"`
}

func (mng DbManager) Create(id string, pw string) error {
	usr := User{
		Email:   id,
		Pw:      pw,
		Enabled: mng.defaultEnabled,
	}
	return mng.CreateUser(usr)
}

func (mng DbManager) CreateUser(usr User) error {

	if usr.Email == "" {
		// todo add email structure verifications
		return errors.New("email cannot be empty")
	}

	if usr.Pw == "" {
		// todo pw length and complexity verification
		return errors.New("password cannot be empty")
	}

	// generate bcrypt hashed password
	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(usr.Pw), mng.bcryptDifficulty)
	if err != nil {
		return err
	}

	usrModel := userModel{
		Name:    usr.Name,
		Email:   usr.Email,
		Pw:      string(hashedPasswd),
		Enabled: usr.Enabled,
	}

	mng.db.Create(&usrModel)
	return nil
}

// GetUser implements userauth.UserGetter. Looks up user by email (id).
func (mng DbManager) GetUser(id string) (userauth.User, error) {
	var m userModel
	err := mng.db.First(&m, "email = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.User{}, userauth.ErrUserNotFound
		}
		return userauth.User{}, err
	}
	return userauth.User{Id: m.Email, HashPw: m.Pw, Enabled: m.Enabled}, nil
}

// GetTOTP implements userauth.TOTPGetter.
func (mng DbManager) GetTOTP(userID string) (userauth.TOTPData, error) {
	var m totpModel
	err := mng.db.First(&m, "user_id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.TOTPData{Enabled: false}, nil
		}
		return userauth.TOTPData{}, err
	}
	return userauth.TOTPData{
		Enabled: m.Enabled,
		Secret:  m.Secret,
	}, nil
}

// SetTOTP is a store method for configuring TOTP.
func (mng DbManager) SetTOTP(userID string, data userauth.TOTPData) error {
	var m totpModel
	err := mng.db.First(&m, "user_id = ?", userID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	m.UserID = userID
	m.Secret = data.Secret
	m.Enabled = data.Enabled
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return mng.db.Create(&m).Error
	}
	return mng.db.Save(&m).Error
}

// SetRecoveryCodes is a store method. Replaces all codes for the user.
func (mng DbManager) SetRecoveryCodes(userID string, hashedCodes []string) error {
	if err := mng.db.Where("user_id = ?", userID).Delete(&recoveryCodeModel{}).Error; err != nil {
		return err
	}
	for _, h := range hashedCodes {
		if h == "" {
			continue
		}
		if err := mng.db.Create(&recoveryCodeModel{UserID: userID, CodeHash: h}).Error; err != nil {
			return err
		}
	}
	return nil
}

// VerifyRecoveryCode implements userauth.TOTPGetter. Consumes the code on success.
func (mng DbManager) VerifyRecoveryCode(userID, code string) (bool, error) {
	hash := hashutil.HashRecoveryCode(code)
	var m recoveryCodeModel
	err := mng.db.Where("user_id = ? AND code_hash = ?", userID, hash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if err := mng.db.Delete(&m).Error; err != nil {
		return false, err
	}
	return true, nil
}

// GetRecoveryCodesCount is a store method.
func (mng DbManager) GetRecoveryCodesCount(userID string) (int, error) {
	var count int64
	err := mng.db.Model(&recoveryCodeModel{}).Where("user_id = ?", userID).Count(&count).Error
	return int(count), err
}

// GenerateEmailVerificationCode is a store method. Generates a one-time code, stores its hash with expiry, returns the plain code.
func (mng DbManager) GenerateEmailVerificationCode(userID string) (code string, expiresAt time.Time, err error) {
	code, err = generateNumericCode(DefaultEmailCodeLength)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(DefaultEmailCodeExpiry)
	hash := hashutil.HashRecoveryCode(code)
	if err := mng.db.Where("user_id = ?", userID).Delete(&emailVerificationCodeModel{}).Error; err != nil {
		return "", time.Time{}, err
	}
	if err := mng.db.Create(&emailVerificationCodeModel{UserID: userID, CodeHash: hash, ExpiresAt: expiresAt}).Error; err != nil {
		return "", time.Time{}, err
	}
	return code, expiresAt, nil
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
	hash := hashutil.HashRecoveryCode(code)
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

// GenerateSMSVerificationCode is a store method. Generates a one-time SMS code, stores its hash with expiry, returns the plain code.
func (mng DbManager) GenerateSMSVerificationCode(userID string) (code string, expiresAt time.Time, err error) {
	code, err = generateNumericCode(DefaultSMSCodeLength)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(DefaultSMSCodeExpiry)
	hash := hashutil.HashRecoveryCode(code)
	if err := mng.db.Where("user_id = ?", userID).Delete(&smsVerificationCodeModel{}).Error; err != nil {
		return "", time.Time{}, err
	}
	if err := mng.db.Create(&smsVerificationCodeModel{UserID: userID, CodeHash: hash, ExpiresAt: expiresAt}).Error; err != nil {
		return "", time.Time{}, err
	}
	return code, expiresAt, nil
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
	hash := hashutil.HashRecoveryCode(code)
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

func generateNumericCode(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("generate code: %w", err)
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}
