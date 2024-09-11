package staticusers

import (
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestUserFromFile(t *testing.T) {
	tcs := []struct {
		name   string
		userId string
		pw     string
		expect bool
	}{
		{
			name:   "expect login true",
			userId: "demo",
			pw:     "demo",
			expect: true,
		},
		{
			name:   "expect  login false on disabled account",
			userId: "user1",
			pw:     "1234",
			expect: false,
		},
		{
			name:   "expect  login false on wrong password account",
			userId: "user1",
			pw:     "12345",
			expect: false,
		},
		{
			name:   "expect user with bcrypt login true",
			userId: "demo1",
			pw:     "demo1",
			expect: true,
		},
		{
			name:   "expect user with sha1 login true",
			userId: "demo2",
			pw:     "demo2",
			expect: true,
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
					got := users.CanLogin(tc.userId, tc.pw)
					if diff := cmp.Diff(got, tc.expect); diff != "" {
						t.Errorf("unexpected value (-got +want)\n%s", diff)
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
		want := "the file does not seem to be a valid htpasswd file"
		if err.Error() != want {
			t.Errorf("want error \"%s\", but got: \"%s\"", want, err.Error())
		}
	})

}
