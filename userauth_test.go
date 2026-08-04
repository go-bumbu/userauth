package userauth

import (
	"github.com/go-bumbu/userauth/internal/hashutil"
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
			name: "bcrypt",
			in:   "demo",
			hash: "$2y$10$ats.g6F4WE1rSeHFqjTIvOArZ7QwQet14gm.g89iRSR7VsrFZDSJq",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			got, err := hashutil.VerifyPassword(tc.in, tc.hash)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, true); diff != "" {
				t.Errorf("expec hash to be valid")
			}
		})
	}
}
func TestCheckHashErrs(t *testing.T) {
	tcs := []struct {
		name string
		in   string
		hash string
		err  string
	}{
		{
			name: "plaintext",
			in:   "demo",
			hash: "demo",
			err:  "unknown crypto algorithm",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hashutil.VerifyPassword(tc.in, tc.hash)

			if diff := cmp.Diff(err.Error(), tc.err); diff != "" {
				t.Errorf("unexpected error: \n%s", diff)
			}
		})
	}
}

func TestUsernameFormatString(t *testing.T) {
	tcs := []struct {
		name   string
		format UsernameFormat
		want   string
	}{
		{name: "any", format: UsernameFormatAny, want: "any"},
		{name: "email", format: UsernameFormatEmail, want: "email"},
		{name: "plain", format: UsernameFormatPlain, want: "plain"},
		{name: "unknown value falls back to any", format: UsernameFormat(42), want: "any"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, tc.format.String()); diff != "" {
				t.Errorf("String() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseUsernameFormat(t *testing.T) {
	tcs := []struct {
		name  string
		input string
		want  UsernameFormat
	}{
		{name: "email", input: "email", want: UsernameFormatEmail},
		{name: "email numeric", input: "1", want: UsernameFormatEmail},
		{name: "plain", input: "plain", want: UsernameFormatPlain},
		{name: "plain numeric", input: "2", want: UsernameFormatPlain},
		{name: "any", input: "any", want: UsernameFormatAny},
		{name: "any numeric", input: "0", want: UsernameFormatAny},
		{name: "empty string", input: "", want: UsernameFormatAny},
		{name: "case insensitive", input: "EMAIL", want: UsernameFormatEmail},
		{name: "mixed case", input: "Plain", want: UsernameFormatPlain},
		{name: "surrounding whitespace", input: "  email  ", want: UsernameFormatEmail},
		{name: "numeric with leading zero", input: "01", want: UsernameFormatEmail},
		{name: "numeric out of range", input: "5", want: UsernameFormatAny},
		{name: "negative numeric", input: "-1", want: UsernameFormatAny},
		{name: "unknown string falls back to any", input: "bogus", want: UsernameFormatAny},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseUsernameFormat(tc.input); got != tc.want {
				t.Errorf("ParseUsernameFormat(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateLoginID(t *testing.T) {
	tcs := []struct {
		name    string
		loginID string
		format  UsernameFormat
		wantErr string
	}{
		{name: "any accepts email", loginID: "user@mail.com", format: UsernameFormatAny},
		{name: "any accepts plain", loginID: "user", format: UsernameFormatAny},
		{name: "any accepts empty", loginID: "", format: UsernameFormatAny},
		{name: "unknown format has no restriction", loginID: "anything@x", format: UsernameFormat(42)},
		{name: "email accepts valid address", loginID: "user@mail.com", format: UsernameFormatEmail},
		{
			name: "email rejects plain username", loginID: "user", format: UsernameFormatEmail,
			wantErr: "username must be a valid email address",
		},
		{
			name: "email rejects empty", loginID: "", format: UsernameFormatEmail,
			wantErr: "username must be a valid email address",
		},
		{name: "plain accepts username", loginID: "user", format: UsernameFormatPlain},
		{
			name: "plain rejects email", loginID: "user@mail.com", format: UsernameFormatPlain,
			wantErr: "username must not be an email address",
		},
		{
			name: "plain rejects any string containing at sign", loginID: "not-an-email@", format: UsernameFormatPlain,
			wantErr: "username must not be an email address",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLoginID(tc.loginID, tc.format)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %q", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if diff := cmp.Diff(tc.wantErr, err.Error()); diff != "" {
				t.Errorf("error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
