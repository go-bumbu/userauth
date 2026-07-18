package loginflow

import (
	"github.com/go-bumbu/userauth"
)

// Policy decides what a login attempt still needs. The engine consults it
// after every verified factor with the factors satisfied so far.
//
// done=true means the requirements are met and the engine may create the
// session; otherwise next lists the method IDs the user may attempt now.
// Policies return decisions only — the engine acts on them; a Policy must
// not perform side effects.
type Policy interface {
	Next(user userauth.User, satisfied []string) (done bool, next []string, err error)
}

// PolicyFunc adapts a function to the Policy interface, for dynamic rules
// (step-up auth, trusted networks, …) that the declarative helpers cannot
// express.
type PolicyFunc func(user userauth.User, satisfied []string) (bool, []string, error)

func (f PolicyFunc) Next(user userauth.User, satisfied []string) (bool, []string, error) {
	return f(user, satisfied)
}

// Chain is an ordered sequence of required method IDs: every factor is
// required, in order.
type Chain []string

// anyPolicy is satisfied when any one chain is fully satisfied.
type anyPolicy struct {
	chains []Chain
}

// RequireAny returns a Policy satisfied when any one of the chains is fully
// satisfied, in order. Examples:
//
//	RequireAny(Chain{"password"})                            // password only
//	RequireAny(Chain{"password", "totp"})                    // password then TOTP, always
//	RequireAny(Chain{"password", "totp"}, Chain{"email"})    // password+TOTP, or email code alone
//
// After each submission the user may continue any chain whose next unmet
// factor is now reachable; Next returns the union of those factors.
func RequireAny(chains ...Chain) Policy {
	return anyPolicy{chains: chains}
}

func (p anyPolicy) Next(_ userauth.User, satisfied []string) (bool, []string, error) {
	var next []string
	for _, chain := range p.chains {
		missing := chainNext(chain, satisfied)
		if missing == "" {
			return true, nil, nil
		}
		if !contains(next, missing) {
			next = append(next, missing)
		}
	}
	return false, next, nil
}

// chainNext returns the first method of the chain not yet satisfied, or ""
// when the whole chain is satisfied.
func chainNext(chain Chain, satisfied []string) string {
	for _, id := range chain {
		if !contains(satisfied, id) {
			return id
		}
	}
	return ""
}

// SecondFactorAfter returns the dynamic policy that matches the semantics of
// userauth.LoginHandler.CanLogin: the first factor alone is enough, unless
// the provider reports enrolled second factors, in which case any one of them
// is additionally required.
//
// The first factor is excluded from the required second factors: a user who
// just proved control of their email is not asked for an email code again.
func SecondFactorAfter(first string, provider userauth.SecondFactorProvider) Policy {
	return PolicyFunc(func(user userauth.User, satisfied []string) (bool, []string, error) {
		if !contains(satisfied, first) {
			return false, []string{first}, nil
		}
		if provider == nil {
			return true, nil, nil
		}
		available, err := provider.AvailableSecondFactors(user.Id)
		if err != nil {
			return false, nil, err
		}
		var next []string
		for _, sf := range available {
			id := string(sf)
			if id == first {
				continue
			}
			if contains(satisfied, id) {
				return true, nil, nil
			}
			next = append(next, id)
		}
		if len(next) == 0 {
			return true, nil, nil
		}
		return false, next, nil
	})
}
