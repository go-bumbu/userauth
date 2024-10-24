package dbusers

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"testing"
	"time"
)

const dbFile = "test.db"

func setup(t *testing.T) *DbManager {

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

	opts := ManagerOpts{
		BcryptDifficulty: bcrypt.MinCost,
	}

	mng, err := NewDbManager(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	return mng

}

func clean() {
	defer func() {
		err := os.Remove(dbFile)
		if err != nil {
			panic(err)
		}
	}()
}

func TestCreateUser(t *testing.T) {

	mng := setup(t)
	defer clean()

	err := mng.CreateUser(User{
		Name:  "test",
		Email: "test@mail.com",
		Pw:    "1234",
	})

	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	// Reads
	var got userModel
	mng.db.First(&got, 1)

	want := userModel{
		Name:  "test",
		Email: "test@mail.com",
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(userModel{}, "Model", "Pw")); diff != "" {
		t.Errorf("Content mismatch (-want +got):\n%s", diff)
	}
}

func TestLogin(t *testing.T) {

	mng := setup(t)
	defer clean()

	_ = mng.CreateUser(User{
		Name:  "test",
		Email: "test@mail.com",
		Pw:    "1234",
	})

	t.Run("assert correct login", func(t *testing.T) {
		got := mng.AllowLogin("test@mail.com", "1234")
		if got != true {
			t.Errorf("expecting login failure")
		}
	})

	t.Run("assert wrong password login", func(t *testing.T) {
		got := mng.AllowLogin("test@mail.com", "12345")
		if got != false {
			t.Errorf("expecting login failure")
		}
	})

	t.Run("assert wrong user name", func(t *testing.T) {
		got := mng.AllowLogin("test_@mail.com", "1234")
		if got != false {
			t.Errorf("expecting login failure")
		}
	})

}
