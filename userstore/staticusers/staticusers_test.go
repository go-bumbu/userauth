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
