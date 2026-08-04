package staticusers

import (
	"github.com/go-bumbu/userauth"
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestUserFromFile(t *testing.T) {
	tcs := []struct {
		name      string
		userId    string
		expect    userauth.User
		expectErr string
	}{
		{
			name:   "get demo user",
			userId: "demo",
			expect: userauth.User{
				Id:      "demo",
				HashPw:  "demo",
				Enabled: true,
			},
		},
		{
			name:      "get non-existent user",
			userId:    "non-exixtent",
			expectErr: "user not found",
		},
	}

	files := map[string]string{
		"yaml": "testdata/users.yaml",
		"json": "testdata/users.json",
	}
	for k, v := range files {
		t.Run(k, func(t *testing.T) {
			file := v
			users, err := FromFile(file)
			if err != nil {
				t.Fatal(err)
			}

			for _, tc := range tcs {
				t.Run(tc.name, func(t *testing.T) {
					got, err := users.GetUser(tc.userId)
					if tc.expectErr != "" {
						if err == nil {
							t.Fatal("expect an error but got none")
						}
						if err.Error() != tc.expectErr {
							t.Fatalf("got unexpected error: %v", err)
						}
					} else {
						if err != nil {
							t.Fatalf("got unexpected error: %v", err)
						}
						if diff := cmp.Diff(got, tc.expect); diff != "" {
							t.Errorf("unexpected value (-got +want)\n%s", diff)
						}
					}
				})
			}
		})
	}

	t.Run("errors", func(t *testing.T) {
		file := "testdata/plain.txt"
		_, err := FromFile(file)
		if err == nil {
			t.Errorf("expecting an error but got none")
		}
		want := "unsupported file format"
		if err.Error() != want {
			t.Errorf("want error \"%s\", but got: \"%s\"", want, err.Error())
		}
	})

}

func TestAvailableSecondFactors(t *testing.T) {
	users, err := FromFile("testdata/users.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name   string
		userID string
		want   []userauth.SecondFactor
	}{
		{
			name:   "no 2FA configured",
			userID: "demo",
			want:   nil,
		},
		{
			name:   "email only",
			userID: "alice",
			want:   []userauth.SecondFactor{userauth.SecondFactorEmail},
		},
		{
			name:   "totp only",
			userID: "bob",
			want:   []userauth.SecondFactor{userauth.SecondFactorTOTP},
		},
		{
			name:   "both email and totp",
			userID: "carol",
			want:   []userauth.SecondFactor{userauth.SecondFactorTOTP, userauth.SecondFactorEmail},
		},
		{
			name:   "unknown user",
			userID: "nobody",
			want:   nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := users.AvailableSecondFactors(tc.userID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("unexpected value (-got +want)\n%s", diff)
			}
		})
	}
}

func TestGetTOTP(t *testing.T) {
	users, err := FromFile("testdata/users.yaml")
	if err != nil {
		t.Fatal(err)
	}

	// the expected secret comes from the fixture file, so the test does not
	// duplicate the credential-looking literal
	var bobSecret string
	for _, u := range users.Users {
		if u.Id == "bob" {
			bobSecret = u.TOTPSecret
		}
	}
	if bobSecret == "" {
		t.Fatal("fixture user bob has no TOTP secret")
	}

	tcs := []struct {
		name   string
		userID string
		want   userauth.TOTPData
	}{
		{
			name:   "user with TOTP secret",
			userID: "bob",
			want:   userauth.TOTPData{Enabled: true, Secret: bobSecret},
		},
		{
			name:   "user without TOTP",
			userID: "demo",
			want:   userauth.TOTPData{Enabled: false, Secret: ""},
		},
		{
			name:   "unknown user",
			userID: "nobody",
			want:   userauth.TOTPData{Enabled: false},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := users.GetTOTP(tc.userID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("unexpected value (-got +want)\n%s", diff)
			}
		})
	}
}

func TestGetUser_Email2FA(t *testing.T) {
	users, err := FromFile("testdata/users.yaml")
	if err != nil {
		t.Fatal(err)
	}

	got, err := users.GetUser("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := userauth.User{
		Id:           "alice",
		HashPw:       "alice",
		Enabled:      true,
		PrimaryEmail: "alice@example.com",
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("unexpected value (-got +want)\n%s", diff)
	}
}
