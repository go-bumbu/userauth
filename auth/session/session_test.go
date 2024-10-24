package session_test

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/auth/session"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"net/http"
	"testing"
)

var _ = spew.Dump // keep spew dependency

func TestProcessSessionData(t *testing.T) {

	tcs := []struct {
		name string
		in   session.SessionData
		want session.SessionData
	}{
		{
			name: "session valid",
			in: session.SessionData{
				UserData: session.UserData{
					IsAuthenticated: true,
				},
				Expiration:  getTime("10m"),
				ForceReAuth: getTime("1m"),
			},
			want: session.SessionData{UserData: session.UserData{IsAuthenticated: true}},
		},
		{
			name: "session expired",
			in: session.SessionData{UserData: session.UserData{IsAuthenticated: true},
				Expiration: getTime("-1s"),
			},
			want: session.SessionData{UserData: session.UserData{IsAuthenticated: false}},
		},
		{
			name: "session NOT expired, but hard logout",
			in: session.SessionData{UserData: session.UserData{IsAuthenticated: true},
				Expiration:  getTime("10m"),
				ForceReAuth: getTime("-1s"),
			},
			want: session.SessionData{UserData: session.UserData{IsAuthenticated: false}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			got := tc.in
			got.Process(0)
			want := tc.want
			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(session.SessionData{}, "Expiration", "ForceReAuth")); diff != "" {
				t.Errorf("Content mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func doReq(client *http.Client, url string, t *testing.T) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// dummyUser  ------------------------------------------------------------

type dummyUser struct {
	user string
	pass string
}

func (st dummyUser) GetUser(id string) (userauth.User, error) {
	if st.user == "" {
		st.user = "admin"
	}
	if st.pass == "" {
		st.pass = userauth.MustHashPw("admin")
	}
	return userauth.User{
		Id:      st.user,
		HashPw:  st.pass,
		Enabled: true,
	}, nil
}
