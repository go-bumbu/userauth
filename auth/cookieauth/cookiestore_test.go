package cookieauth_test

import (
	"testing"

	"github.com/go-bumbu/userauth/auth/cookieauth"
	"github.com/gorilla/securecookie"
)

func TestNewFsStore(t *testing.T) {
	tcs := []struct {
		name     string
		hashKey  []byte
		blockKey []byte
		wantErr  bool
	}{
		{
			name:     "valid keys",
			hashKey:  securecookie.GenerateRandomKey(32),
			blockKey: securecookie.GenerateRandomKey(16),
		},
		{
			name:     "invalid hash key length",
			hashKey:  securecookie.GenerateRandomKey(10),
			blockKey: securecookie.GenerateRandomKey(32),
			wantErr:  true,
		},
		{
			name:     "invalid block key length",
			hashKey:  securecookie.GenerateRandomKey(64),
			blockKey: securecookie.GenerateRandomKey(10),
			wantErr:  true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			store, err := cookieauth.NewFsStore(t.TempDir(), tc.hashKey, tc.blockKey)
			checkStoreResult(t, store != nil, err, tc.wantErr)
		})
	}
}

func TestNewCookieStore(t *testing.T) {
	tcs := []struct {
		name     string
		hashKey  []byte
		blockKey []byte
		wantErr  bool
	}{
		{
			name:     "valid keys",
			hashKey:  securecookie.GenerateRandomKey(64),
			blockKey: securecookie.GenerateRandomKey(24),
		},
		{
			name:     "invalid hash key length",
			hashKey:  securecookie.GenerateRandomKey(16),
			blockKey: securecookie.GenerateRandomKey(32),
			wantErr:  true,
		},
		{
			name:     "invalid block key length",
			hashKey:  securecookie.GenerateRandomKey(32),
			blockKey: securecookie.GenerateRandomKey(8),
			wantErr:  true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			store, err := cookieauth.NewCookieStore(tc.hashKey, tc.blockKey)
			checkStoreResult(t, store != nil, err, tc.wantErr)
		})
	}
}

func checkStoreResult(t *testing.T, gotStore bool, err error, wantErr bool) {
	t.Helper()
	if wantErr {
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if gotStore {
			t.Error("expected nil store on error")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotStore {
		t.Error("expected a store instance, got nil")
	}
}
