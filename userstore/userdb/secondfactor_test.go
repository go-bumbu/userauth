package userdb

import (
	"testing"

	"github.com/go-bumbu/userauth"
	"github.com/google/go-cmp/cmp"
)

const demoTOTPSecret = "JBSWY3DPEHPK3PXP" //nolint:gosec // well-known RFC example secret, not a credential

func TestAvailableSecondFactors(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "sf-user")

	assertFactors := func(t *testing.T, want []userauth.SecondFactor) {
		t.Helper()
		got, err := mng.AvailableSecondFactors(userID)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("second factors mismatch (-want +got):\n%s", diff)
		}
	}

	t.Run("none configured", func(t *testing.T) {
		assertFactors(t, nil)
	})

	t.Run("totp enabled", func(t *testing.T) {
		if err := mng.SetTOTP(userID, userauth.TOTPData{Enabled: true, Secret: demoTOTPSecret}); err != nil {
			t.Fatal(err)
		}
		assertFactors(t, []userauth.SecondFactor{userauth.SecondFactorTOTP})
	})

	t.Run("totp and email enabled", func(t *testing.T) {
		if err := mng.SetEmailCodeEnabled(userID, true); err != nil {
			t.Fatal(err)
		}
		assertFactors(t, []userauth.SecondFactor{userauth.SecondFactorTOTP, userauth.SecondFactorEmail})
	})

	t.Run("all three enabled", func(t *testing.T) {
		if err := mng.SetSMSCodeEnabled(userID, true); err != nil {
			t.Fatal(err)
		}
		assertFactors(t, []userauth.SecondFactor{
			userauth.SecondFactorTOTP, userauth.SecondFactorEmail, userauth.SecondFactorSMS,
		})
	})

	t.Run("totp disabled leaves email and sms", func(t *testing.T) {
		if err := mng.SetTOTP(userID, userauth.TOTPData{Enabled: false, Secret: demoTOTPSecret}); err != nil {
			t.Fatal(err)
		}
		assertFactors(t, []userauth.SecondFactor{userauth.SecondFactorEmail, userauth.SecondFactorSMS})
	})
}
