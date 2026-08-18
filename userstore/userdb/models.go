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

// pendingEmailChangeModel stores a pending email change awaiting code verification.
// It stays in the user store, unlike the other one-time codes: committing the
// new address is a user-profile write, and the row exists only to hold the
// change until the code confirms it.
type pendingEmailChangeModel struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"uniqueIndex;not null"`
	NewEmail  string    `gorm:"not null"`
	CodeHash  string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

func (pendingEmailChangeModel) TableName() string { return "user_pending_email_changes" }
