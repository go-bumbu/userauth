package userdb

import (
	"errors"

	"gorm.io/gorm"
)

// Bootstrap creates the given users only if the store contains no users at
// all. It is intended for initial admin provisioning (e.g. from environment
// variables or a first-run setup endpoint): calling it on every startup is
// safe, it becomes a no-op as soon as any user exists — including after the
// bootstrapped users themselves are deleted or replaced.
//
// The emptiness check and the inserts run in a single transaction, so
// concurrent callers cannot both seed the store.
//
// Users with PwIsHashed set store Pw as-is (it must be a valid bcrypt hash);
// otherwise Pw is hashed like in CreateUser.
//
// It returns true if the users were created, false if the store already had
// users and nothing was done.
func (s Store) Bootstrap(users ...User) (bool, error) {
	if len(users) == 0 {
		return false, errors.New("bootstrap: at least one user is required")
	}
	seeded := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var total int64
		if err := tx.Model(&userModel{}).Count(&total).Error; err != nil {
			return err
		}
		if total > 0 {
			return nil
		}
		for _, usr := range users {
			if err := s.createUser(tx, usr); err != nil {
				return err
			}
		}
		seeded = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return seeded, nil
}
