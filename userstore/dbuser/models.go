package dbuser

import (
	"time"

	"gorm.io/gorm"
)

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
