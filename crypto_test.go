package userauth

import (
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestCheckHash(t *testing.T) {
	tcs := []struct {
		name string
		in   string
		hash string
	}{
		{
			name: "plaintext",
			in:   "demo",
			hash: "demo",
		},
		{
			name: "sha1",
			in:   "demo",
			hash: "{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE=",
		},
		{
			name: "bcrypt",
			in:   "demo",
			hash: "$2y$10$ats.g6F4WE1rSeHFqjTIvOArZ7QwQet14gm.g89iRSR7VsrFZDSJq",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			got, err := CheckPass(tc.in, tc.hash)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, true); diff != "" {
				t.Errorf("expec hash to be valid")
			}
		})
	}
}
