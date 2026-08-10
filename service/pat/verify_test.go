package pat_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
)

// erroringUsers fails every lookup with a non-credential error.
type erroringUsers struct{}

func (erroringUsers) GetUser(string) (userauth.User, error) {
	return userauth.User{}, errors.New("db down")
}
func (erroringUsers) GetUserByLogin(string) (userauth.User, error) {
	return userauth.User{}, errors.New("db down")
}

func TestVerifyHappyPath(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{})
	plaintext, rec, err := svc.Mint("u1", "api", []string{"read"}, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	info, ok, err := svc.Verify(plaintext)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if info.UserID != "u1" || info.LoginID != "alice@example.com" ||
		info.TokenID != rec.TokenID || info.Name != "api" ||
		len(info.Scopes) != 1 || info.Scopes[0] != "read" {
		t.Errorf("TokenInfo mismatch: %+v", info)
	}
}

func TestVerifyCredentialFailures(t *testing.T) {
	svc, store := newTestService(t, pat.Opts{})
	plaintext, rec, err := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// a token whose user is disabled
	plainDisabled, _, err := svc.Mint("u2", "disabled owner", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint u2: %v", err)
	}
	// a token that is already expired: insert directly, bypassing Mint validation
	past := time.Now().Add(-time.Minute)
	expired := rec
	expired.TokenID = "expired1"
	expired.ExpiresAt = &past
	if err := store.Insert(expired); err != nil {
		t.Fatalf("Insert expired: %v", err)
	}

	tests := []struct {
		name      string
		presented string
	}{
		{"malformed", "garbage"},
		{"wrong prefix", "xxx_AAAAAAAA_" + plaintext[len(plaintext)-43:]},
		{"unknown tokenID", "pat_ZZZZZZZZ_" + plaintext[len(plaintext)-43:]},
		{"wrong secret", plaintext[:len(plaintext)-43] + "WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGWRO"},
		{"expired", "pat_expired1_" + plaintext[len(plaintext)-43:]},
		{"disabled user", plainDisabled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, ok, err := svc.Verify(tc.presented)
			if err != nil {
				t.Fatalf("credential failure must not return error: %v", err)
			}
			if ok {
				t.Error("Verify should fail")
			}
			// TokenInfo contains a slice, so compare fields, not the struct
			if info.UserID != "" || info.TokenID != "" || info.Scopes != nil {
				t.Errorf("failed Verify must return zero TokenInfo, got %+v", info)
			}
		})
	}
}

func TestVerifyExpiredNotWrongSecret(t *testing.T) {
	// The expired case in the table above reuses u1's secret with a different
	// tokenID, so its hash does not match; this test pins the expiry branch
	// specifically: correct secret, expired record.
	svc, store := newTestService(t, pat.Opts{})
	plaintext, rec, err := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	rec.ExpiresAt = &past
	// replace the record with an expired copy under the same tokenID
	if err := store.Delete("u1", rec.TokenID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Insert(rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, ok, err := svc.Verify(plaintext); ok || err != nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Error("expired token must fail verification")
	}
}

func TestVerifyUserStoreErrorSurfaces(t *testing.T) {
	store := memory.New()
	svc, err := pat.NewService(store, erroringUsers{}, pat.Opts{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// Mint does not consult the user store, so minting succeeds even though
	// every user lookup fails; Verify then hits the failing lookup.
	plaintext, _, err := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, _, err := svc.Verify(plaintext); err == nil {
		t.Error("user-store I/O failure must surface as error")
	}
}

func TestVerifyTouchThrottling(t *testing.T) {
	t.Run("first verify touches", func(t *testing.T) {
		svc, store := newTestService(t, pat.Opts{})
		plaintext, rec, _ := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
		if _, ok, _ := svc.Verify(plaintext); !ok {
			t.Fatal("Verify failed")
		}
		got, _ := store.GetByTokenID(rec.TokenID)
		if got.LastUsedAt == nil {
			t.Error("first Verify should set LastUsedAt")
		}
	})
	t.Run("within interval does not touch again", func(t *testing.T) {
		svc, store := newTestService(t, pat.Opts{TouchInterval: time.Hour})
		plaintext, rec, _ := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
		if _, ok, _ := svc.Verify(plaintext); !ok {
			t.Fatal("Verify failed")
		}
		first, _ := store.GetByTokenID(rec.TokenID)
		if _, ok, _ := svc.Verify(plaintext); !ok {
			t.Fatal("second Verify failed")
		}
		second, _ := store.GetByTokenID(rec.TokenID)
		if !second.LastUsedAt.Equal(*first.LastUsedAt) {
			t.Error("LastUsedAt must not change within the throttle interval")
		}
	})
	t.Run("negative interval disables writes", func(t *testing.T) {
		svc, store := newTestService(t, pat.Opts{TouchInterval: -1})
		plaintext, rec, _ := svc.Mint("u1", "api", nil, nil, pat.HashOnly)
		if _, ok, _ := svc.Verify(plaintext); !ok {
			t.Fatal("Verify failed")
		}
		got, _ := store.GetByTokenID(rec.TokenID)
		if got.LastUsedAt != nil {
			t.Error("negative TouchInterval must disable LastUsedAt writes")
		}
	})
}
