package totp_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/cipher"
	"github.com/go-bumbu/userauth/service/totp"
	totpmemory "github.com/go-bumbu/userauth/service/totp/store/memory"
	otptotp "github.com/pquerna/otp/totp"
)

func testKey() []byte { return bytes.Repeat([]byte{0x17}, 32) }

// newService returns a service over a fresh in-memory store.
func newService(t *testing.T, opts totp.Opts) (*totp.Service, *totpmemory.Store) {
	t.Helper()
	if opts.Issuer == "" {
		opts.Issuer = "test-issuer"
	}
	store := totpmemory.New()
	svc, err := totp.NewService(store, opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

// code generates a currently valid code for the secret.
func code(t *testing.T, secret string) string {
	t.Helper()
	c, err := otptotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return c
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := totp.NewService(nil, totp.Opts{Issuer: "x"}); err == nil {
		t.Error("nil store should error")
	}
	if _, err := totp.NewService(totpmemory.New(), totp.Opts{}); err == nil {
		t.Error("empty issuer should error")
	}
}

func TestEnrollStoresPendingRecord(t *testing.T) {
	svc, store := newService(t, totp.Opts{})

	enr, err := svc.Enroll("user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enr.Secret == "" {
		t.Error("Enroll returned an empty secret")
	}
	if !strings.HasPrefix(enr.URI, "otpauth://totp/") {
		t.Errorf("URI = %q, want an otpauth://totp/ URI", enr.URI)
	}
	if !strings.Contains(enr.URI, "test-issuer") || !strings.Contains(enr.URI, "alice@example.com") {
		t.Errorf("URI = %q, want issuer and account name in it", enr.URI)
	}

	rec, err := store.Get("user1")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.Enabled {
		t.Error("a fresh enrolment must be stored disabled until confirmed")
	}
	if rec.Secret != enr.Secret {
		t.Errorf("stored secret = %q, want the returned one (no cipher configured)", rec.Secret)
	}

	// not usable as a factor yet
	if ok, err := svc.Verify("user1", code(t, enr.Secret)); err != nil || ok {
		t.Errorf("Verify on pending enrolment = (%v, %v), want (false, nil)", ok, err)
	}
	if enabled, err := svc.Enabled("user1"); err != nil || enabled {
		t.Errorf("Enabled on pending enrolment = (%v, %v), want (false, nil)", enabled, err)
	}
}

func TestEnrollValidation(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	if _, err := svc.Enroll("", "alice"); err == nil {
		t.Error("empty userID should error")
	}
	if _, err := svc.Enroll("user1", ""); err == nil {
		t.Error("empty accountName should error")
	}
}

func TestConfirmWrongCodeKeepsEnrolmentPending(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	enr, err := svc.Enroll("user1", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	ok, err := svc.Confirm("user1", "000000")
	if err != nil {
		t.Fatalf("Confirm with wrong code: unexpected error %v", err)
	}
	if ok {
		t.Error("Confirm with a wrong code must report false")
	}
	if enabled, _ := svc.Enabled("user1"); enabled {
		t.Error("a failed Confirm must not enable the factor")
	}
	// the user can retry with the same secret
	if ok, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil || !ok {
		t.Errorf("retry Confirm = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestConfirmEnablesAndVerifyWorks(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	enr, err := svc.Enroll("user1", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	ok, err := svc.Confirm("user1", code(t, enr.Secret))
	if err != nil || !ok {
		t.Fatalf("Confirm = (%v, %v), want (true, nil)", ok, err)
	}
	if enabled, err := svc.Enabled("user1"); err != nil || !enabled {
		t.Errorf("Enabled after Confirm = (%v, %v), want (true, nil)", enabled, err)
	}
	if ok, err := svc.Verify("user1", code(t, enr.Secret)); err != nil || !ok {
		t.Errorf("Verify = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := svc.Verify("user1", "000000"); err != nil || ok {
		t.Errorf("Verify with wrong code = (%v, %v), want (false, nil)", ok, err)
	}
	// idempotent: confirming an enabled factor is the same check
	if ok, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil || !ok {
		t.Errorf("Confirm on enabled factor = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestConfirmWithoutEnrolment(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	if _, err := svc.Confirm("user1", "123456"); !errors.Is(err, totp.ErrNotEnrolled) {
		t.Errorf("Confirm without enrolment: err = %v, want totp.ErrNotEnrolled", err)
	}
}

// TestVerifyUnknownUserIsNotAnError pins the contract that lets policies call
// Verify blindly: a user with no enrolment is a "no", not a 500.
func TestVerifyUnknownUserIsNotAnError(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	if ok, err := svc.Verify("nobody", "123456"); err != nil || ok {
		t.Errorf("Verify unknown user = (%v, %v), want (false, nil)", ok, err)
	}
	if enabled, err := svc.Enabled("nobody"); err != nil || enabled {
		t.Errorf("Enabled unknown user = (%v, %v), want (false, nil)", enabled, err)
	}
}

func TestDisableRemovesTheSecret(t *testing.T) {
	svc, store := newService(t, totp.Opts{})
	enr, _ := svc.Enroll("user1", "alice")
	if _, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	if err := svc.Disable("user1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := store.Get("user1"); !errors.Is(err, totp.ErrNotEnrolled) {
		t.Errorf("after Disable the record must be gone, got err = %v", err)
	}
	if ok, err := svc.Verify("user1", code(t, enr.Secret)); err != nil || ok {
		t.Errorf("Verify after Disable = (%v, %v), want (false, nil)", ok, err)
	}
	// disabling a user with no enrolment is not an error
	if err := svc.Disable("nobody"); err != nil {
		t.Errorf("Disable without enrolment: %v", err)
	}
}

func TestEnrollReplacesAPendingEnrolment(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	first, _ := svc.Enroll("user1", "alice")
	second, err := svc.Enroll("user1", "alice")
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if first.Secret == second.Secret {
		t.Error("re-enrolling should generate a new secret")
	}
	if ok, _ := svc.Confirm("user1", code(t, first.Secret)); ok {
		t.Error("the superseded secret must no longer confirm")
	}
	if ok, err := svc.Confirm("user1", code(t, second.Secret)); err != nil || !ok {
		t.Errorf("Confirm with the current secret = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestPendingResumesEnrolment(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})

	if _, ok, err := svc.Pending("user1", "alice"); err != nil || ok {
		t.Errorf("Pending without enrolment = (%v, %v), want (false, nil)", ok, err)
	}

	enr, _ := svc.Enroll("user1", "alice")
	got, ok, err := svc.Pending("user1", "alice")
	if err != nil || !ok {
		t.Fatalf("Pending after Enroll = (%v, %v), want (true, nil)", ok, err)
	}
	if got.Secret != enr.Secret {
		t.Errorf("Pending secret = %q, want the pending one %q", got.Secret, enr.Secret)
	}
	if !strings.Contains(got.URI, enr.Secret) {
		t.Errorf("Pending URI %q should carry the secret", got.URI)
	}

	// once confirmed there is nothing pending
	if _, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if _, ok, err := svc.Pending("user1", "alice"); err != nil || ok {
		t.Errorf("Pending after Confirm = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestCipherEncryptsSecretAtRest(t *testing.T) {
	c, err := cipher.NewAESGCM(testKey(), "k1")
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	svc, store := newService(t, totp.Opts{Cipher: c})

	enr, err := svc.Enroll("user1", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	rec, err := store.Get("user1")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.Secret == enr.Secret {
		t.Error("the stored secret must not be the plaintext")
	}
	if rec.KeyID != "k1" {
		t.Errorf("stored KeyID = %q, want k1", rec.KeyID)
	}
	// and the round-trip still works
	if ok, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil || !ok {
		t.Errorf("Confirm with encrypted secret = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := svc.Verify("user1", code(t, enr.Secret)); err != nil || !ok {
		t.Errorf("Verify with encrypted secret = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestLegacyCiphertextWithoutKeyID guards the migration promise: secrets
// encrypted by the pre-service userdb code path were written with no AAD and no
// key id, and must keep decrypting once the service owns the cipher.
func TestLegacyCiphertextWithoutKeyID(t *testing.T) {
	c, _ := cipher.NewAESGCM(testKey(), "k1")
	svc, store := newService(t, totp.Opts{Cipher: c})

	const secret = "JBSWY3DPEHPK3PXP"       //nolint:gosec // well-known RFC example secret, not a credential
	legacy, _, err := c.Encrypt(secret, "") // no context, as the old path wrote it
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// stored with an empty KeyID, as a row written before the column existed
	if err := store.Set("user1", totp.Record{Secret: legacy, Enabled: true}); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	ok, err := svc.Verify("user1", code(t, secret))
	if err != nil {
		t.Fatalf("Verify on a legacy row: %v", err)
	}
	if !ok {
		t.Error("a secret encrypted by the old code path must still verify")
	}
}

func TestNoCipherForEncryptedSecret(t *testing.T) {
	svc, store := newService(t, totp.Opts{}) // no cipher
	if err := store.Set("user1", totp.Record{Secret: "ciphertext", KeyID: "k1", Enabled: true}); err != nil {
		t.Fatalf("store.Set: %v", err)
	}
	if _, err := svc.Verify("user1", "123456"); !errors.Is(err, totp.ErrNoCipher) {
		t.Errorf("Verify = %v, want totp.ErrNoCipher", err)
	}
}

func TestVerifyRejectsEmptyCode(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	enr, _ := svc.Enroll("user1", "alice")
	if _, err := svc.Confirm("user1", code(t, enr.Secret)); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if ok, err := svc.Verify("user1", ""); err != nil || ok {
		t.Errorf("Verify with empty code = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestQRPNG(t *testing.T) {
	svc, _ := newService(t, totp.Opts{})
	enr, _ := svc.Enroll("user1", "alice")

	png, err := totp.QRPNG(enr.URI, 220)
	if err != nil {
		t.Fatalf("QRPNG: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Error("QRPNG did not return a PNG")
	}
	if _, err := totp.QRPNG(enr.URI, 0); err == nil {
		t.Error("non-positive size should error")
	}
	if _, err := totp.QRPNG("not-a-uri", 220); err == nil {
		t.Error("a malformed URI should error")
	}
}

// fakeGetter is a read-only TOTP source, standing in for staticusers.
type fakeGetter struct {
	data userauth.TOTPData
	err  error
}

func (f fakeGetter) GetTOTP(string) (userauth.TOTPData, error) { return f.data, f.err }

func TestFromGetter(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" //nolint:gosec // well-known RFC example secret, not a credential

	v, err := totp.FromGetter(fakeGetter{data: userauth.TOTPData{Enabled: true, Secret: secret}}, 0)
	if err != nil {
		t.Fatalf("FromGetter: %v", err)
	}
	if enabled, err := v.Enabled("user1"); err != nil || !enabled {
		t.Errorf("Enabled = (%v, %v), want (true, nil)", enabled, err)
	}
	if ok, err := v.Verify("user1", code(t, secret)); err != nil || !ok {
		t.Errorf("Verify = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := v.Verify("user1", "000000"); err != nil || ok {
		t.Errorf("Verify wrong code = (%v, %v), want (false, nil)", ok, err)
	}

	// a disabled entry never verifies, even with a valid code
	off, _ := totp.FromGetter(fakeGetter{data: userauth.TOTPData{Enabled: false, Secret: secret}}, 0)
	if ok, err := off.Verify("user1", code(t, secret)); err != nil || ok {
		t.Errorf("disabled Verify = (%v, %v), want (false, nil)", ok, err)
	}

	// store failures surface as errors, not as credential failures
	boom := errors.New("store down")
	bad, _ := totp.FromGetter(fakeGetter{err: boom}, 0)
	if _, err := bad.Verify("user1", "123456"); !errors.Is(err, boom) {
		t.Errorf("Verify with a failing getter: err = %v, want %v", err, boom)
	}
	if _, err := bad.Enabled("user1"); !errors.Is(err, boom) {
		t.Errorf("Enabled with a failing getter: err = %v, want %v", err, boom)
	}

	if _, err := totp.FromGetter(nil, 0); err == nil {
		t.Error("nil getter should error")
	}
}
