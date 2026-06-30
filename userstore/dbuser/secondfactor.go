package dbuser

import (
	"github.com/go-bumbu/userauth"
)

// AvailableSecondFactors implements userauth.SecondFactorProvider.
func (s Store) AvailableSecondFactors(userID string) ([]userauth.SecondFactor, error) {
	var out []userauth.SecondFactor
	totpData, err := s.GetTOTP(userID)
	if err != nil {
		return nil, err
	}
	if totpData.Enabled {
		out = append(out, userauth.SecondFactorTOTP)
	}
	emailEnabled, err := s.emailCodeEnabled(userID)
	if err != nil {
		return nil, err
	}
	if emailEnabled {
		out = append(out, userauth.SecondFactorEmail)
	}
	smsEnabled, err := s.smsCodeEnabled(userID)
	if err != nil {
		return nil, err
	}
	if smsEnabled {
		out = append(out, userauth.SecondFactorSMS)
	}
	return out, nil
}
