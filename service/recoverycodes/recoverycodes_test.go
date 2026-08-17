package recoverycodes_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/recoverycodes"
	recmemory "github.com/go-bumbu/userauth/service/recoverycodes/store/memory"
)

func newService(t *testing.T, opts recoverycodes.Opts) (*recoverycodes.Service, *recmemory.Store) {
	t.Helper()
	store := recmemory.New()
	svc, err := recoverycodes.NewService(store, opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := recoverycodes.NewService(nil, recoverycodes.Opts{}); err == nil {
		t.Error("nil store should error")
	}
	if _, err := recoverycodes.NewService(recmemory.New(), recoverycodes.Opts{Count: -1}); err == nil {
		t.Error("negative count should error")
	}
	if _, err := recoverycodes.NewService(recmemory.New(), recoverycodes.Opts{Count: 1000}); err == nil {
		t.Error("count over the maximum should error")
	}
}

func TestIssueReturnsPlaintextAndStoresHashes(t *testing.T) {
	svc, store := newService(t, recoverycodes.Opts{})

	codes, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(codes) != recoverycodes.DefaultCount {
		t.Errorf("issued %d codes, want the default %d", len(codes), recoverycodes.DefaultCount)
	}
	// the codes must be distinct — a repeated code is a wasted slot
	seen := map[string]bool{}
	for _, c := range codes {
		if c == "" {
			t.Error("issued an empty code")
		}
		if seen[c] {
			t.Errorf("code %q was issued twice", c)
		}
		seen[c] = true
	}

	hashes, err := store.Hashes("user1")
	if err != nil {
		t.Fatalf("store.Hashes: %v", err)
	}
	if len(hashes) != len(codes) {
		t.Fatalf("stored %d hashes for %d codes", len(hashes), len(codes))
	}
	for _, h := range hashes {
		if slices.Contains(codes, h) {
			t.Error("a plaintext code was stored instead of its hash")
		}
	}

	n, err := svc.Remaining("user1")
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if n != len(codes) {
		t.Errorf("Remaining = %d, want %d", n, len(codes))
	}
}

func TestIssueHonoursCount(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{Count: 3})
	codes, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(codes) != 3 {
		t.Errorf("issued %d codes, want 3", len(codes))
	}
}

func TestIssueValidation(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{})
	if _, err := svc.Issue(""); err == nil {
		t.Error("empty userID should error")
	}
}

func TestVerifyConsumesEachCodeOnce(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{Count: 3})
	codes, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	for i, c := range codes {
		ok, err := svc.VerifyRecoveryCode("user1", c)
		if err != nil || !ok {
			t.Fatalf("code %d: Verify = (%v, %v), want (true, nil)", i, ok, err)
		}
		// the same code must not work a second time
		ok, err = svc.VerifyRecoveryCode("user1", c)
		if err != nil {
			t.Fatalf("code %d: replay errored: %v", i, err)
		}
		if ok {
			t.Errorf("code %d verified twice — codes must be single use", i)
		}
		want := len(codes) - i - 1
		if n, _ := svc.Remaining("user1"); n != want {
			t.Errorf("after consuming %d codes Remaining = %d, want %d", i+1, n, want)
		}
	}
}

func TestVerifyWrongAndEmptyCode(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{Count: 2})
	if _, err := svc.Issue("user1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if ok, err := svc.VerifyRecoveryCode("user1", "not-a-code"); err != nil || ok {
		t.Errorf("wrong code = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := svc.VerifyRecoveryCode("user1", ""); err != nil || ok {
		t.Errorf("empty code = (%v, %v), want (false, nil)", ok, err)
	}
	// a wrong guess must not consume anything
	if n, _ := svc.Remaining("user1"); n != 2 {
		t.Errorf("Remaining after wrong guesses = %d, want 2", n)
	}
}

// TestVerifyUnknownUserIsNotAnError pins the contract the login engine relies
// on: a user with no codes is a "no", not a 500.
func TestVerifyUnknownUserIsNotAnError(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{})
	if ok, err := svc.VerifyRecoveryCode("nobody", "abc"); err != nil || ok {
		t.Errorf("Verify for unknown user = (%v, %v), want (false, nil)", ok, err)
	}
	if n, err := svc.Remaining("nobody"); err != nil || n != 0 {
		t.Errorf("Remaining for unknown user = (%v, %v), want (0, nil)", n, err)
	}
}

func TestIssueReplacesPreviousCodes(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{Count: 2})
	first, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("re-Issue: %v", err)
	}

	for _, c := range first {
		if ok, _ := svc.VerifyRecoveryCode("user1", c); ok {
			t.Error("a superseded code still verified")
		}
	}
	if ok, err := svc.VerifyRecoveryCode("user1", second[0]); err != nil || !ok {
		t.Errorf("current code = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestClear(t *testing.T) {
	svc, _ := newService(t, recoverycodes.Opts{Count: 2})
	codes, err := svc.Issue("user1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := svc.Clear("user1"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n, _ := svc.Remaining("user1"); n != 0 {
		t.Errorf("Remaining after Clear = %d, want 0", n)
	}
	if ok, _ := svc.VerifyRecoveryCode("user1", codes[0]); ok {
		t.Error("a cleared code still verified")
	}
}

// failingStore reports a failure for every read, standing in for a database
// that went away.
type failingStore struct{ err error }

func (f failingStore) Replace(string, []string) error  { return f.err }
func (f failingStore) Hashes(string) ([]string, error) { return nil, f.err }
func (f failingStore) Delete(string, string) error     { return f.err }
func (f failingStore) Count(string) (int, error)       { return 0, f.err }

func TestStoreFailuresSurfaceAsErrors(t *testing.T) {
	boom := errors.New("store down")
	svc, err := recoverycodes.NewService(failingStore{err: boom}, recoverycodes.Opts{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.VerifyRecoveryCode("user1", "abc"); !errors.Is(err, boom) {
		t.Errorf("Verify: err = %v, want %v", err, boom)
	}
	if _, err := svc.Issue("user1"); !errors.Is(err, boom) {
		t.Errorf("Issue: err = %v, want %v", err, boom)
	}
	if _, err := svc.Remaining("user1"); !errors.Is(err, boom) {
		t.Errorf("Remaining: err = %v, want %v", err, boom)
	}
	if err := svc.Clear("user1"); !errors.Is(err, boom) {
		t.Errorf("Clear: err = %v, want %v", err, boom)
	}
}

// the service is the login engine's recovery verifier
var _ userauth.RecoveryCodeVerifier = (*recoverycodes.Service)(nil)
