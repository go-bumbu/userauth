package userdb

import (
	"time"
)

// userModel is the database representation of the user.
//
// UUID is the stable canonical identity: it is generated at creation, never
// changes, and is what every other table (and the rest of the application:
// sessions, verifiers, satellite rows) keys on. LoginID is the mutable login
// identifier (username or email) and is only used to find the user at login.
//
// Rows are always hard-deleted (no soft-delete column): a deleted user's
// login ID must be immediately reusable, and auth data should not linger.
type userModel struct {
	ID                   uint   `gorm:"primaryKey"`
	UUID                 string `gorm:"uniqueIndex;not null"`
	LoginID              string `gorm:"uniqueIndex;not null"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Name                 string
	Pw                   string
	Enabled              bool
	PrimaryEmail         string
	PrimaryEmailVerified bool
	BackupEmail          string
	BackupEmailVerified  bool
}

// groupModel stores one group membership per row (user_groups table,
// UserID = user UUID). Group values are opaque to the library: they are
// identity facts ("who is this user"), never policy — what a membership
// permits is defined entirely by the consuming application.
// The column is group_name (not "group") to keep raw SQL free of reserved-word
// quoting across dialects.
type groupModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index:idx_user_group,unique;not null"`
	Group     string `gorm:"column:group_name;index:idx_user_group,unique;not null"`
	CreatedAt time.Time
}

func (groupModel) TableName() string { return "user_groups" }

// totpModel stores TOTP secret and enabled flag per user (UserID = user UUID).
type totpModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"uniqueIndex;not null"`
	Secret    string `gorm:"not null"`
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (totpModel) TableName() string { return "user_totp" }

// recoveryCodeModel stores one recovery code hash per row (user_recovery_codes table).
type recoveryCodeModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index;not null"`
	CodeHash  string `gorm:"not null"`
	CreatedAt time.Time
}

func (recoveryCodeModel) TableName() string { return "user_recovery_codes" }

// emailVerificationCodeModel stores one email verification code per user (user_email_verification_codes table).
// Replaced on each GenerateEmailVerificationCode.
type emailVerificationCodeModel struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"uniqueIndex;not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

func (emailVerificationCodeModel) TableName() string { return "user_email_verification_codes" }

// smsVerificationCodeModel stores one SMS verification code per user (user_sms_verification_codes table).
type smsVerificationCodeModel struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"uniqueIndex;not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

func (smsVerificationCodeModel) TableName() string { return "user_sms_verification_codes" }

// secondFactorFlagsModel stores per-user flags for email/SMS 2FA (user_second_factor_flags table).
type secondFactorFlagsModel struct {
	ID           uint   `gorm:"primaryKey"`
	UserID       string `gorm:"uniqueIndex;not null"`
	EmailEnabled bool
	SMSEnabled   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (secondFactorFlagsModel) TableName() string { return "user_second_factor_flags" }

// pendingEmailChangeModel stores a pending email change awaiting code verification.
type pendingEmailChangeModel struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"uniqueIndex;not null"`
	NewEmail  string    `gorm:"not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

func (pendingEmailChangeModel) TableName() string { return "user_pending_email_changes" }

// patModel stores one personal access token per row (user_pats table,
// UserID = user UUID). SecretHash is the SHA-256 hex of the token's secret
// part; the plaintext is never stored. Scopes is a JSON-encoded []string —
// opaque to the library, interpreted only by the consuming application.
type patModel struct {
	ID         uint   `gorm:"primaryKey"`
	TokenID    string `gorm:"uniqueIndex;not null"`
	UserID     string `gorm:"index;not null"`
	Name       string `gorm:"not null"`
	SecretHash string `gorm:"not null"`
	SecretEnc  string // encrypted secret (cipher output); empty for hash-only tokens
	KeyID      string // cipher key id for SecretEnc; empty for hash-only
	Scopes     string // JSON-encoded []string; empty when no scopes
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

func (patModel) TableName() string { return "user_pats" }
