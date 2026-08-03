package userdb

import (
	"errors"
	"fmt"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/internal/hashutil"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User is the input struct for CreateUser (login ID and optional email fields).
type User struct {
	Name                 string `yaml:"name"`
	LoginID              string `yaml:"login_id"` // unique login identifier (required)
	Pw                   string `yaml:"pw"`
	PwIsHashed           bool   `yaml:"pw_is_hashed"` // when true, Pw is a bcrypt hash and is stored as-is
	Enabled              bool   `yaml:"enabled"`
	PrimaryEmail         string `yaml:"primary_email"`
	PrimaryEmailVerified bool   `yaml:"primary_email_verified"`
	BackupEmail          string `yaml:"backup_email"`
	BackupEmailVerified  bool   `yaml:"backup_email_verified"`
}

func (s Store) Create(id string, pw string) error {
	if err := userauth.ValidateLoginID(id, s.usernameFormat); err != nil {
		return err
	}
	usr := User{
		LoginID: id,
		Pw:      pw,
		Enabled: s.defaultEnabled,
	}
	return s.CreateUser(usr)
}

// CreateUser creates a user. When usr.PwIsHashed is true, Pw must be a valid
// bcrypt hash and is stored as-is; otherwise Pw is hashed before storing.
func (s Store) CreateUser(usr User) error {
	return s.createUser(s.db, usr)
}

// createUser is the shared create path; db may be the store handle or a transaction.
func (s Store) createUser(db *gorm.DB, usr User) error {
	if usr.LoginID == "" {
		return errors.New("login ID cannot be empty")
	}
	if usr.Pw == "" {
		return errors.New("password cannot be empty")
	}

	pw := usr.Pw
	if usr.PwIsHashed {
		if hashutil.Alg(usr.Pw) == hashutil.Unknown {
			return fmt.Errorf("password for user %q is flagged as hashed but is not a recognized bcrypt hash", usr.LoginID)
		}
	} else {
		hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(usr.Pw), s.bcryptDifficulty)
		if err != nil {
			return err
		}
		pw = string(hashedPasswd)
	}

	usrModel := userModel{
		Name:                 usr.Name,
		LoginID:              usr.LoginID,
		Pw:                   pw,
		Enabled:              usr.Enabled,
		PrimaryEmail:         usr.PrimaryEmail,
		PrimaryEmailVerified: usr.PrimaryEmailVerified,
		BackupEmail:          usr.BackupEmail,
		BackupEmailVerified:  usr.BackupEmailVerified,
	}

	return db.Create(&usrModel).Error
}

// CreateUserWithHashedPassword creates a user with a pre-hashed password.
// Unlike CreateUser, this does not hash the password - it stores it directly.
// The password must be a valid bcrypt hash.
func (s Store) CreateUserWithHashedPassword(usr User) error {
	usr.PwIsHashed = true
	return s.createUser(s.db, usr)
}

// toUser maps the stored row to the public userauth.User.
func (m userModel) toUser() userauth.User {
	return userauth.User{
		Id:                   m.LoginID,
		HashPw:               m.Pw,
		Enabled:              m.Enabled,
		PrimaryEmail:         m.PrimaryEmail,
		PrimaryEmailVerified: m.PrimaryEmailVerified,
		BackupEmail:          m.BackupEmail,
		BackupEmailVerified:  m.BackupEmailVerified,
	}
}

// GetUser implements userauth.UserGetter. Looks up user by login ID.
func (s Store) GetUser(id string) (userauth.User, error) {
	var m userModel
	err := s.db.First(&m, "login_id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userauth.User{}, userauth.ErrUserNotFound
		}
		return userauth.User{}, err
	}
	return m.toUser(), nil
}

// Count returns the total number of users in the store.
func (s Store) Count() (int64, error) {
	var total int64
	err := s.db.Model(&userModel{}).Count(&total).Error
	return total, err
}

// IsEmpty reports whether the store contains no users. Useful to decide
// whether an initial admin bootstrap or a first-run setup flow is needed.
func (s Store) IsEmpty() (bool, error) {
	total, err := s.Count()
	return total == 0, err
}

// Delete permanently removes a user and all associated data (TOTP config,
// recovery codes, verification codes, second-factor flags, pending email
// changes). The row is hard-deleted so the login ID can be reused.
// Returns userauth.ErrUserNotFound if the user does not exist.
func (s Store) Delete(userID string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Unscoped().Where("login_id = ?", userID).Delete(&userModel{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return userauth.ErrUserNotFound
		}
		for _, m := range []interface{}{
			&totpModel{}, &recoveryCodeModel{}, &emailVerificationCodeModel{},
			&smsVerificationCodeModel{}, &secondFactorFlagsModel{}, &pendingEmailChangeModel{},
		} {
			if err := tx.Unscoped().Where("user_id = ?", userID).Delete(m).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// ListOpts controls pagination for List.
type ListOpts struct {
	Limit  int // max rows to return; <=0 uses defaultListLimit, capped at maxListLimit
	Offset int // rows to skip; <0 is treated as 0
}

// ListResult is a page of users plus the total count.
type ListResult struct {
	Users []userauth.User // page of users, ordered by login_id ASC
	Total int             // total number of users, ignoring Limit/Offset
}

// List returns a page of users ordered by login ID, plus the total user count
// so callers can render "page X of Y".
func (s Store) List(opts ListOpts) (ListResult, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	var total int64
	if err := s.db.Model(&userModel{}).Count(&total).Error; err != nil {
		return ListResult{}, err
	}

	var rows []userModel
	if err := s.db.Order("login_id ASC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return ListResult{}, err
	}

	users := make([]userauth.User, 0, len(rows))
	for _, m := range rows {
		users = append(users, m.toUser())
	}
	return ListResult{Users: users, Total: int(total)}, nil
}

// SetPrimaryEmail updates the primary email for a user. Resets PrimaryEmailVerified to false.
func (s Store) SetPrimaryEmail(userID, email string) error {
	return s.db.Model(&userModel{}).Where("login_id = ?", userID).
		Updates(map[string]interface{}{
			"primary_email":          email,
			"primary_email_verified": false,
		}).Error
}

// SetPrimaryEmailVerified sets the primary email verified flag for a user.
func (s Store) SetPrimaryEmailVerified(userID string, verified bool) error {
	return s.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("primary_email_verified", verified).Error
}

// SetEnabled sets the enabled flag for a user.
func (s Store) SetEnabled(userID string, enabled bool) error {
	return s.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("enabled", enabled).Error
}

// SetPasswordHash updates the password hash for an existing user.
// The hash should be a valid bcrypt hash. This method does not hash the input.
func (s Store) SetPasswordHash(userID, hashedPw string) error {
	return s.db.Model(&userModel{}).Where("login_id = ?", userID).
		Update("pw", hashedPw).Error
}
