package userauth_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
)

// fakeCodeStore is an in-test CodeStore: it keeps the last stored hash/expiry per
// user and consumes on an exact hash match when not expired.
type fakeCodeStore struct {
	hash    map[string]string
	expires map[string]time.Time
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{hash: map[string]string{}, expires: map[string]time.Time{}}
}

func (f *fakeCodeStore) StoreCode(userID, hash string, expiresAt time.Time) error {
	f.hash[userID] = hash
	f.expires[userID] = expiresAt
	return nil
}

func (f *fakeCodeStore) ConsumeCode(userID, hash string) (bool, error) {
	stored, ok := f.hash[userID]
	if !ok || stored != hash || time.Now().After(f.expires[userID]) {
		return false, nil
	}
	delete(f.hash, userID)
	delete(f.expires, userID)
	return true, nil
}

func TestVerificationCodeService_GenerateThenVerify(t *testing.T) {
	store := newFakeCodeStore()
	svc := userauth.NewVerificationCodeService(store, userauth.VerificationCodeOpts{CodeLength: 6, Expiry: time.Minute})

	code, _, err := svc.Generate("u")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("want 6-digit code, got %q", code)
	}
	ok, err := svc.Verify("u", code)
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
}

func TestVerificationCodeService_OneTimeConsume(t *testing.T) {
	store := newFakeCodeStore()
	svc := userauth.NewVerificationCodeService(store, userauth.VerificationCodeOpts{})
	code, _, _ := svc.Generate("u")

	if ok, _ := svc.Verify("u", code); !ok {
		t.Fatal("first verify should succeed")
	}
	if ok, _ := svc.Verify("u", code); ok {
		t.Fatal("second verify should fail — code consumed")
	}
}

func TestVerificationCodeService_WrongCode(t *testing.T) {
	store := newFakeCodeStore()
	svc := userauth.NewVerificationCodeService(store, userauth.VerificationCodeOpts{})
	_, _, _ = svc.Generate("u")

	if ok, _ := svc.Verify("u", "000000"); ok {
		t.Fatal("wrong code should not verify")
	}
}

func TestVerificationCodeService_DefaultsApplied(t *testing.T) {
	store := newFakeCodeStore()
	svc := userauth.NewVerificationCodeService(store, userauth.VerificationCodeOpts{}) // zero opts

	code, expiresAt, _ := svc.Generate("u")
	if len(code) != 6 {
		t.Fatalf("default length should be 6, got %d", len(code))
	}
	if expiresAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("default expiry should be ~10m out, got %v", expiresAt)
	}
}

// Compile-time check that the service satisfies the login verifier interface.
var _ userauth.CodeVerifier = (*userauth.VerificationCodeService)(nil)
