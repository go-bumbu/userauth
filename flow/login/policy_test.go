package login_test

import (
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/flow/login"
	"github.com/google/go-cmp/cmp"
)

func TestRequireAny(t *testing.T) {
	tcs := []struct {
		name      string
		chains    []login.Chain
		satisfied []string
		wantDone  bool
		wantNext  []string
	}{
		{
			name:     "single factor, nothing satisfied",
			chains:   []login.Chain{{"password"}},
			wantNext: []string{"password"},
		},
		{
			name:      "single factor satisfied",
			chains:    []login.Chain{{"password"}},
			satisfied: []string{"password"},
			wantDone:  true,
		},
		{
			name:      "chain requires factors in order",
			chains:    []login.Chain{{"password", "totp"}},
			satisfied: []string{"password"},
			wantNext:  []string{"totp"},
		},
		{
			name:      "chain complete",
			chains:    []login.Chain{{"password", "totp"}},
			satisfied: []string{"password", "totp"},
			wantDone:  true,
		},
		{
			name:     "alternative chains offer both entry points",
			chains:   []login.Chain{{"password", "totp"}, {"email"}},
			wantNext: []string{"password", "email"},
		},
		{
			name:      "one complete chain wins even if another is partial",
			chains:    []login.Chain{{"password", "totp"}, {"email"}},
			satisfied: []string{"email"},
			wantDone:  true,
		},
		{
			name:      "email+totp composition",
			chains:    []login.Chain{{"email", "totp"}},
			satisfied: []string{"email"},
			wantNext:  []string{"totp"},
		},
		{
			name:     "duplicate next factors are deduplicated",
			chains:   []login.Chain{{"password", "totp"}, {"password", "email"}},
			wantNext: []string{"password"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			p := login.RequireAny(tc.chains...)
			done, next, err := p.Next(userauth.User{Id: "u"}, tc.satisfied)
			if err != nil {
				t.Fatal(err)
			}
			if done != tc.wantDone {
				t.Errorf("done: want %v, got %v", tc.wantDone, done)
			}
			if diff := cmp.Diff(tc.wantNext, next); diff != "" {
				t.Errorf("next mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// sfProvider is a static SecondFactorProvider for tests.
type sfProvider map[string][]userauth.SecondFactor

func (p sfProvider) AvailableSecondFactors(userID string) ([]userauth.SecondFactor, error) {
	return p[userID], nil
}

func TestSecondFactorAfter(t *testing.T) {
	provider := sfProvider{
		"with2fa": {userauth.SecondFactorTOTP, userauth.SecondFactorEmail},
		"plain":   nil,
	}
	p := login.SecondFactorAfter("password", provider)

	tcs := []struct {
		name      string
		userID    string
		satisfied []string
		wantDone  bool
		wantNext  []string
	}{
		{
			name:     "first factor always required first",
			userID:   "with2fa",
			wantNext: []string{"password"},
		},
		{
			name:      "no enrolled factors: password is enough",
			userID:    "plain",
			satisfied: []string{"password"},
			wantDone:  true,
		},
		{
			name:      "enrolled factors demanded after password",
			userID:    "with2fa",
			satisfied: []string{"password"},
			wantNext:  []string{"totp", "email"},
		},
		{
			name:      "any one enrolled factor completes",
			userID:    "with2fa",
			satisfied: []string{"password", "email"},
			wantDone:  true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			done, next, err := p.Next(userauth.User{Id: tc.userID}, tc.satisfied)
			if err != nil {
				t.Fatal(err)
			}
			if done != tc.wantDone {
				t.Errorf("done: want %v, got %v", tc.wantDone, done)
			}
			if diff := cmp.Diff(tc.wantNext, next); diff != "" {
				t.Errorf("next mismatch (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("first factor excluded from second factors", func(t *testing.T) {
		// A user whose only enrolled second factor is email, logging in via
		// email code: proving email control twice adds nothing, so done.
		provider := sfProvider{"u": {userauth.SecondFactorEmail}}
		p := login.SecondFactorAfter("email", provider)
		done, _, err := p.Next(userauth.User{Id: "u"}, []string{"email"})
		if err != nil {
			t.Fatal(err)
		}
		if !done {
			t.Error("email-first login must not require an email second factor")
		}
	})
}
