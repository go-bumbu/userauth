// Package invite manages invite codes for gated user registration.
//
// The Service owns the policy (code generation, defaults); persistence is
// delegated to a Store. Invites are admin-facing artifacts: they can be
// issued, listed and revoked independently of any registration flow, and the
// register package consumes them through a small interface at account
// creation time.
//
// Codes are stored in plaintext, deliberately: unlike one-time verification
// codes they must be listable by an admin, and they are long random strings
// (default 12 alphanumeric characters, ~62 bits of entropy), not user
// secrets derived from a small space.
package invite

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DefaultCodeLength is the length of generated invite codes.
const DefaultCodeLength = 12

const codeCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// ErrInviteNotFound is returned by Store.Get when no invite has the code.
var ErrInviteNotFound = errors.New("invite not found")

// Invite is one invite code with its usage constraints.
type Invite struct {
	Code      string    // the plaintext code handed to the invitee
	Note      string    // optional admin note (who it is for, campaign, …)
	Email     string    // optional binding: only this email may consume it
	UsesLeft  int       // remaining uses; issued with at least 1
	ExpiresAt time.Time // zero means the invite never expires
	CreatedAt time.Time
	Revoked   bool
}

// Usable reports whether the invite can still be consumed by the given
// email at time now. Store implementations use it to keep Consume semantics
// consistent.
func (i Invite) Usable(email string, now time.Time) bool {
	if i.Revoked || i.UsesLeft <= 0 {
		return false
	}
	if !i.ExpiresAt.IsZero() && now.After(i.ExpiresAt) {
		return false
	}
	if i.Email != "" && i.Email != email {
		return false
	}
	return true
}

// Store is pure persistence for invites; it never generates codes.
//
// Consume must atomically decrement UsesLeft of a usable invite (not
// revoked, not expired, uses left, matching email binding). It returns
// (false, nil) for any invalid-code-shaped reason — unknown code included —
// and reserves errors for storage failures.
type Store interface {
	Save(inv Invite) error
	Get(code string) (Invite, error)
	List() ([]Invite, error)
	Delete(code string) error
	Consume(code, email string) (bool, error)
}

// Opts configures a Service. Zero-valued fields fall back to defaults.
type Opts struct {
	CodeLength int // generated code length; default DefaultCodeLength
}

// Service owns invite policy: code generation and defaults. Persistence is
// delegated to a Store. It satisfies the register package's InviteConsumer.
type Service struct {
	store   Store
	codeLen int
}

// New wires the service to a Store and applies defaults for zero-valued
// options.
func New(store Store, opts Opts) *Service {
	if opts.CodeLength <= 0 {
		opts.CodeLength = DefaultCodeLength
	}
	return &Service{store: store, codeLen: opts.CodeLength}
}

// IssueOpts describes the invite to create. Zero-valued fields mean:
// single use, no expiry, no email binding, no note.
type IssueOpts struct {
	Uses      int       // number of allowed uses; <=0 means 1
	ExpiresAt time.Time // zero means never expires
	Email     string    // optional: bind the invite to one email
	Note      string    // optional admin note
}

// Issue generates a fresh code and persists the invite.
func (s *Service) Issue(opts IssueOpts) (Invite, error) {
	code, err := generateCode(s.codeLen)
	if err != nil {
		return Invite{}, err
	}
	inv := Invite{
		Code:      code,
		Note:      opts.Note,
		Email:     opts.Email,
		UsesLeft:  opts.Uses,
		ExpiresAt: opts.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}
	if inv.UsesLeft <= 0 {
		inv.UsesLeft = 1
	}
	if err := s.store.Save(inv); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// List returns all invites, including revoked and exhausted ones.
func (s *Service) List() ([]Invite, error) {
	return s.store.List()
}

// Revoke marks the invite as no longer consumable. Revoking an unknown code
// returns ErrInviteNotFound.
func (s *Service) Revoke(code string) error {
	inv, err := s.store.Get(code)
	if err != nil {
		return err
	}
	inv.Revoked = true
	return s.store.Save(inv)
}

// Validate reports whether the code could currently be consumed by the given
// email. It is a read-only courtesy check: only Consume is authoritative.
// Any invalid-code-shaped reason yields (false, nil).
func (s *Service) Validate(code, email string) (bool, error) {
	inv, err := s.store.Get(code)
	if err != nil {
		if errors.Is(err, ErrInviteNotFound) {
			return false, nil
		}
		return false, err
	}
	return inv.Usable(email, time.Now()), nil
}

// Consume atomically uses up one use of the invite. It returns (false, nil)
// when the invite is unknown, revoked, expired, exhausted, or bound to a
// different email.
func (s *Service) Consume(code, email string) (bool, error) {
	return s.store.Consume(code, email)
}

func generateCode(length int) (string, error) {
	b := make([]byte, length)
	max := big.NewInt(int64(len(codeCharset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("invite: generate code: %w", err)
		}
		b[i] = codeCharset[n.Int64()]
	}
	return string(b), nil
}
