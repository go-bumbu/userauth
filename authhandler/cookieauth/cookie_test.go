package cookieauth_test

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/authhandler/cookieauth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func getTime(add string) time.Time {
	if add == "" {
		add = "0s"
	}
	dur, err := time.ParseDuration(add)
	if err != nil {
		panic(err)
	}
	return time.Now().Add(dur)
}

func TestProcessSessionData(t *testing.T) {
	tcs := []struct {
		name string
		in   cookieauth.SessionData
		want cookieauth.SessionData
	}{
		{
			name: "session valid",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("10m"), ForceReAuth: getTime("1m"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: true}},
		},
		{
			name: "session expired",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("-1s"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: false}},
		},
		{
			name: "session NOT expired, but hard logout",
			in: cookieauth.SessionData{
				UserData:   cookieauth.UserData{IsAuthenticated: true},
				Expiration: getTime("10m"), ForceReAuth: getTime("-1s"),
			},
			want: cookieauth.SessionData{UserData: cookieauth.UserData{IsAuthenticated: false}},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in
			got.Verify()
			want := tc.want
			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(cookieauth.SessionData{}, "Expiration", "ForceReAuth")); diff != "" {
				t.Errorf("Content mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
