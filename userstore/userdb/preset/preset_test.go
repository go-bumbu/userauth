package preset_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/totp"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newStores(t *testing.T) preset.Stores {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := preset.Full(db, userdb.Opts{BcryptDifficulty: bcrypt.MinCost, DefaultEnabled: true})
	if err != nil {
		t.Fatalf("preset.Full: %v", err)
	}
	return s
}

func newUser(t *testing.T, s preset.Stores, login string) userauth.User {
	t.Helper()
	if err := s.Users.Create(login, "secret"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	u, err := s.Users.GetUserByLogin(login)
	if err != nil {
		t.Fatalf("GetUserByLogin: %v", err)
	}
	return u
}

// TestFullCascadesEverySatellite is the guarantee the monolith used to give for
// free: a deleted user's login ID is reusable immediately, so no credential of
// theirs may survive anywhere.
func TestFullCascadesEverySatellite(t *testing.T) {
	s := newStores(t)
	u := newUser(t, s, "alice@example.com")

	if err := s.TOTP.Set(u.ID, totp.Record{Secret: "s", Enabled: true}); err != nil {
		t.Fatalf("TOTP.Set: %v", err)
	}
	if err := s.Recovery.Replace(u.ID, []string{"h1", "h2"}); err != nil {
		t.Fatalf("Recovery.Replace: %v", err)
	}
	if err := s.PATs.Insert(pat.TokenRecord{
		TokenID: "t1", UserID: u.ID, Name: "n", SecretHash: "h", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("PATs.Insert: %v", err)
	}
	if err := s.EmailCodes.StoreCode(u.ID, "ch", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("EmailCodes.StoreCode: %v", err)
	}
	if err := s.SMSCodes.StoreCode(u.ID, "sh", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("SMSCodes.StoreCode: %v", err)
	}
	if err := s.Flags.SetEnabled(u.ID, userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("Flags.SetEnabled: %v", err)
	}

	if err := s.Users.Delete(u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.TOTP.Get(u.ID); !errors.Is(err, totp.ErrNotEnrolled) {
		t.Errorf("TOTP record survived: %v", err)
	}
	if n, err := s.Recovery.Count(u.ID); err != nil || n != 0 {
		t.Errorf("recovery codes survived: (%d, %v)", n, err)
	}
	if _, err := s.PATs.GetByTokenID("t1"); !errors.Is(err, pat.ErrTokenNotFound) {
		t.Errorf("PAT survived: %v", err)
	}
	if ok, _ := s.EmailCodes.ConsumeCode(u.ID, "ch", 5); ok {
		t.Error("email code survived")
	}
	if ok, _ := s.SMSCodes.ConsumeCode(u.ID, "sh", 5); ok {
		t.Error("SMS code survived")
	}
	if on, _ := s.Flags.Enabled(u.ID, userauth.SecondFactorEmail); on {
		t.Error("second-factor flag survived")
	}
}

// TestProviderReflectsRealState wires the composed provider end to end: it must
// report a confirmed TOTP enrolment and a stored email preference, and nothing
// for a user who has neither.
func TestProviderReflectsRealState(t *testing.T) {
	s := newStores(t)
	u := newUser(t, s, "bob@example.com")

	got, err := s.Provider.AvailableSecondFactors(u.ID)
	if err != nil {
		t.Fatalf("AvailableSecondFactors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("factors for a fresh user = %v, want none", got)
	}

	if err := s.TOTP.Set(u.ID, totp.Record{Secret: "s", Enabled: true}); err != nil {
		t.Fatalf("TOTP.Set: %v", err)
	}
	if err := s.Flags.SetEnabled(u.ID, userauth.SecondFactorEmail, true); err != nil {
		t.Fatalf("Flags.SetEnabled: %v", err)
	}

	got, err = s.Provider.AvailableSecondFactors(u.ID)
	if err != nil {
		t.Fatalf("AvailableSecondFactors: %v", err)
	}
	if len(got) != 2 || got[0] != userauth.SecondFactorTOTP || got[1] != userauth.SecondFactorEmail {
		t.Errorf("factors = %v, want [totp email]", got)
	}
}

// TestFullErrorOnClosedDB covers the error paths in Full by passing a closed
// database connection, which causes the first AutoMigrate to fail.
func TestFullErrorOnClosedDB(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get underlying DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close DB: %v", err)
	}

	_, err = preset.Full(db, userdb.Opts{BcryptDifficulty: bcrypt.MinCost})
	if err == nil {
		t.Error("Full with closed DB returned nil error, want error")
	}
}
