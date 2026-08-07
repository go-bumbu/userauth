package pat

import (
	"github.com/go-bumbu/userauth/auth/tokenauth"
)

// ChainVerifier returns a tokenauth.Verifier backed by this service, for
// wiring into an auth chain. The adapter lives here (not in tokenauth) so
// auth/tokenauth stays free of a dependency on service/pat.
func (s *Service) ChainVerifier() tokenauth.Verifier {
	return chainVerifier{s}
}

type chainVerifier struct{ s *Service }

func (v chainVerifier) Verify(token string) (tokenauth.RequestData, bool, error) {
	info, ok, err := v.s.Verify(token)
	if !ok || err != nil {
		return tokenauth.RequestData{}, ok, err
	}
	return tokenauth.RequestData{
		UserID:  info.UserID,
		LoginID: info.LoginID,
		TokenID: info.TokenID,
		Name:    info.Name,
		Scopes:  info.Scopes,
	}, true, nil
}
