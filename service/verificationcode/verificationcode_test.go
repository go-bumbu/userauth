package verificationcode_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/verificationcode"
)

// fakeCodeStore is an in-test CodeStore: it keeps the last stored hash/expiry per
// user and consumes on an exact hash match when not expired. It records the
// maxAttempts the service passed and counts wrong guesses against it.
type fakeCodeStore struct {
	hash        map[string]string
	expires     map[string]time.Time
	attempts    map[string]int
	maxAttempts int // last value received from the service
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{hash: map[string]string{}, expires: map[string]time.Time{}, attempts: map[string]int{}}
}

func (f *fakeCodeStore) StoreCode(userID, hash string, expiresAt time.Time) error {
	f.hash[userID] = hash
	f.expires[userID] = expiresAt
	delete(f.attempts, userID)
	return nil
}

func (f *fakeCodeStore) ConsumeCode(userID, hash string, maxAttempts int) (bool, error) {
	f.maxAttempts = maxAttempts
	stored, ok := f.hash[userID]
	if !ok || time.Now().After(f.expires[userID]) {
		return false, nil
	}
	if stored != hash {
		f.attempts[userID]++
		if f.attempts[userID] >= maxAttempts {
			delete(f.hash, userID)
			delete(f.expires, userID)
			delete(f.attempts, userID)
		}
		return false, nil
	}
	delete(f.hash, userID)
	delete(f.expires, userID)
	delete(f.attempts, userID)
	return true, nil
}

func TestVerificationCodeService_GenerateThenVerify(t *testing.T) {
	store := newFakeCodeStore()
	svc := verificationcode.NewService(store, verificationcode.Opts{CodeLength: 6, Expiry: time.Minute})

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
	svc := verificationcode.NewService(store, verificationcode.Opts{})
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
	svc := verificationcode.NewService(store, verificationcode.Opts{})
	_, _, _ = svc.Generate("u")

	if ok, _ := svc.Verify("u", "000000"); ok {
		t.Fatal("wrong code should not verify")
	}
}

func TestVerificationCodeService_DefaultsApplied(t *testing.T) {
	store := newFakeCodeStore()
	svc := verificationcode.NewService(store, verificationcode.Opts{}) // zero opts

	code, expiresAt, _ := svc.Generate("u")
	if len(code) != 6 {
		t.Fatalf("default length should be 6, got %d", len(code))
	}
	if expiresAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("default expiry should be ~10m out, got %v", expiresAt)
	}
	_, _ = svc.Verify("u", code)
	if store.maxAttempts != 5 {
		t.Fatalf("default max attempts should be 5, got %d", store.maxAttempts)
	}
}

func TestVerificationCodeService_MaxAttemptsPassedToStore(t *testing.T) {
	store := newFakeCodeStore()
	svc := verificationcode.NewService(store, verificationcode.Opts{MaxAttempts: 3})
	code, _, _ := svc.Generate("u")

	if ok, _ := svc.Verify("u", "999999"); ok {
		t.Fatal("wrong code should not verify")
	}
	if store.maxAttempts != 3 {
		t.Fatalf("service should pass MaxAttempts=3 to the store, got %d", store.maxAttempts)
	}
	// Two more wrong guesses exhaust the limit and invalidate the code.
	_, _ = svc.Verify("u", "999999")
	_, _ = svc.Verify("u", "999999")
	if ok, _ := svc.Verify("u", code); ok {
		t.Fatal("correct code should be invalid after attempts are exhausted")
	}
}

// Compile-time check that the service satisfies the login verifier interface.
var _ verificationcode.CodeVerifier = (*verificationcode.Service)(nil)
