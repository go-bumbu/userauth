package secondfactor_test

import (
	"errors"
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/secondfactor"
)

type stub struct {
	on  bool
	err error
}

func (s stub) Available(_ string) (bool, error) { return s.on, s.err }

func TestProviderReportsOnlyWiredAndEnabledFactors(t *testing.T) {
	tests := []struct {
		name string
		p    secondfactor.Provider
		want []userauth.SecondFactor
	}{
		{
			name: "nothing wired reports nothing",
			p:    secondfactor.Provider{},
			want: nil,
		},
		{
			name: "an unwired factor is never probed",
			p:    secondfactor.Provider{TOTP: stub{on: true}},
			want: []userauth.SecondFactor{userauth.SecondFactorTOTP},
		},
		{
			name: "a wired but disabled factor is not reported",
			p:    secondfactor.Provider{TOTP: stub{on: false}, Email: stub{on: true}},
			want: []userauth.SecondFactor{userauth.SecondFactorEmail},
		},
		{
			name: "order is TOTP, email, SMS regardless of wiring order",
			p:    secondfactor.Provider{SMS: stub{on: true}, TOTP: stub{on: true}, Email: stub{on: true}},
			want: []userauth.SecondFactor{
				userauth.SecondFactorTOTP, userauth.SecondFactorEmail, userauth.SecondFactorSMS,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.p.AvailableSecondFactors("u1")
			if err != nil {
				t.Fatalf("AvailableSecondFactors: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A store failure must surface, not read as "the user has no second factor" —
// that would silently drop a required factor and weaken the login.
func TestProviderPropagatesErrors(t *testing.T) {
	boom := errors.New("store down")
	p := secondfactor.Provider{TOTP: stub{err: boom}}
	if _, err := p.AvailableSecondFactors("u1"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the store error", err)
	}
}

func TestProviderSatisfiesTheRootInterface(t *testing.T) {
	var _ userauth.SecondFactorProvider = secondfactor.Provider{}
}
