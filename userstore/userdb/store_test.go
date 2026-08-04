package userdb

import (
	"log"
	"os"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupOpts is like setup but lets the test control the store options
// (e.g. username format or TOTP encryption key).
func setupOpts(t *testing.T, opts Opts) *Store {
	t.Helper()

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Silent,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic("failed to connect database")
	}

	mng, err := New(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	return mng
}

// mustCreateUser creates a user and returns its canonical ID (UUID).
func mustCreateUser(t *testing.T, mng *Store, loginID string) string {
	t.Helper()
	if err := mng.CreateUser(User{LoginID: loginID, Pw: "pw", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	u, err := mng.GetUserByLogin(loginID)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestNewInvalidTOTPKey(t *testing.T) {
	defer clean()

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{LogLevel: logger.Silent},
	)
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: newLogger})
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(db, Opts{TOTPEncryptionKey: []byte("too-short")})
	if err == nil {
		t.Fatal("expected error for non 32-byte TOTP encryption key")
	}
}

func TestNewValidTOTPKey(t *testing.T) {
	defer clean()

	key := make([]byte, 32)
	mng := setupOpts(t, Opts{TOTPEncryptionKey: key})
	if mng == nil {
		t.Fatal("expected a store instance")
	}
}
