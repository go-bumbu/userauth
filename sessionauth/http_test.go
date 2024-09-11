package sessionauth_test

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestJsonAuthHandler(t *testing.T) {

	tcs := []struct {
		name     string
		password string
		expect   int
	}{
		{
			name:     "valid login",
			password: "admin",
			expect:   200,
		},
		{
			name:     "invalid login",
			password: "nope",
			expect:   401,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, useFsStore)
			defer svr.Close()

			// perform login
			var jsonStr = []byte(`{"user":"admin","password":"` + tc.password + `"}`)
			request, err := http.NewRequest("POST", svr.URL+"/json-login", bytes.NewBuffer(jsonStr))
			request.Header.Set("Content-Type", "application/json")

			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}

			want := tc.expect
			if response.StatusCode != want {
				t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, response.StatusCode)
			}
		})
	}
}

func TestFormAuthHandler(t *testing.T) {

	tcs := []struct {
		name     string
		password string
		expect   int
	}{
		{
			name:     "valid login",
			password: "admin",
			expect:   200,
		},
		{
			name:     "invalid login",
			password: "nope",
			expect:   401,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			svr, client := testServer(50*time.Millisecond, 500*time.Millisecond, 5*time.Minute, useFsStore)
			defer svr.Close()

			// perform login
			var param = url.Values{}

			param.Set("User", "admin")
			param.Set("Pw", tc.password)

			var payload = bytes.NewBufferString(param.Encode())
			request, err := http.NewRequest("POST", svr.URL+"/form-login", payload)

			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}

			want := tc.expect
			if response.StatusCode != want {
				t.Errorf("[login request] got unexpected response code expected: %d, got: %d", want, response.StatusCode)
			}
		})
	}
}
