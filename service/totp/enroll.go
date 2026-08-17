package totp

import (
	"errors"
	"fmt"

	"github.com/pquerna/otp/totp"
)

// Enrolment is what a user needs to add the account to an authenticator app.
// Both fields carry the shared secret, so neither may be logged or stored by
// the caller: show them once and drop them.
type Enrolment struct {
	// Secret is the base32 shared secret, for manual entry.
	Secret string
	// URI is the otpauth:// URI every authenticator app understands, for a QR
	// code (see QRPNG).
	URI string
}

// Enroll generates a fresh secret for the user and stores it *disabled*: the
// factor only counts once Confirm has seen a working code, so a user who
// abandons enrolment is never locked into a secret they cannot produce codes
// for. Calling it again replaces a pending — or an existing, confirmed —
// enrolment, so callers that want to protect an active factor should check
// Enabled first.
//
// accountName is the label shown in the authenticator app next to the issuer;
// pass something the user recognises (their login ID or email), not an opaque
// internal ID.
func (s *Service) Enroll(userID, accountName string) (Enrolment, error) {
	if userID == "" {
		return Enrolment{}, fmt.Errorf("totp: userID is required")
	}
	if accountName == "" {
		return Enrolment{}, fmt.Errorf("totp: accountName is required")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer, AccountName: accountName})
	if err != nil {
		return Enrolment{}, fmt.Errorf("totp: generate secret: %w", err)
	}
	stored, keyID, err := s.encrypt(key.Secret())
	if err != nil {
		return Enrolment{}, err
	}
	if err := s.store.Set(userID, Record{Secret: stored, KeyID: keyID, Enabled: false}); err != nil {
		return Enrolment{}, err
	}
	s.logger.Debug("totp: enrolment started", "user", userID)
	return Enrolment{Secret: key.Secret(), URI: key.URL()}, nil
}

// Confirm completes enrolment: it validates the user's first code against the
// pending secret and, on success, enables the factor. It reports false for a
// wrong code (the secret stays pending, so the user can retry) and
// ErrNotEnrolled when there is nothing to confirm.
//
// Confirming an already-enabled factor is allowed and idempotent — it is the
// same check with nothing left to change.
func (s *Service) Confirm(userID, code string) (bool, error) {
	rec, err := s.store.Get(userID)
	if err != nil {
		return false, err
	}
	secret, err := s.decrypt(rec)
	if err != nil {
		return false, err
	}
	if !s.validate(code, secret) {
		return false, nil
	}
	if rec.Enabled {
		return true, nil
	}
	rec.Enabled = true
	if err := s.store.Set(userID, rec); err != nil {
		return false, err
	}
	s.logger.Info("totp: enabled", "user", userID)
	return true, nil
}

// Disable removes the user's TOTP enrolment, pending or confirmed. The secret
// is deleted rather than flagged off: a disabled factor that keeps its secret
// is a credential nobody is watching. Re-enabling means enrolling again.
//
// Recovery codes are a separate factor with their own service — a caller
// turning off two-factor authentication as a whole should clear those too.
func (s *Service) Disable(userID string) error {
	if err := s.store.Delete(userID); err != nil {
		return err
	}
	s.logger.Info("totp: disabled", "user", userID)
	return nil
}

// Enabled reports whether the user has a confirmed TOTP factor. A pending
// enrolment reports false, and so does an absent one — policies asking "should
// I demand a code from this user" get the same answer either way, which is why
// this returns a plain bool rather than surfacing ErrNotEnrolled.
func (s *Service) Enabled(userID string) (bool, error) {
	rec, err := s.store.Get(userID)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return false, nil
		}
		return false, err
	}
	return rec.Enabled, nil
}

// Pending reports whether the user has an unconfirmed enrolment, and returns it
// so a resumed setup page can re-render the same QR code instead of generating
// a new secret. ok is false when there is no record or it is already confirmed.
func (s *Service) Pending(userID, accountName string) (e Enrolment, ok bool, err error) {
	rec, err := s.store.Get(userID)
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return Enrolment{}, false, nil
		}
		return Enrolment{}, false, err
	}
	if rec.Enabled {
		return Enrolment{}, false, nil
	}
	secret, err := s.decrypt(rec)
	if err != nil {
		return Enrolment{}, false, err
	}
	uri, err := buildURI(s.issuer, accountName, secret)
	if err != nil {
		return Enrolment{}, false, err
	}
	return Enrolment{Secret: secret, URI: uri}, true, nil
}
