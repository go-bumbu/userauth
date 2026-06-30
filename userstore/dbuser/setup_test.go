package dbuser

import (
	"log"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const dbFile = "test.db"

func setup(t *testing.T) *Store {

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

	opts := Opts{
		BcryptDifficulty: bcrypt.MinCost,
	}

	mng, err := New(db, opts)
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
