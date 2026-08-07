package pat_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	flowpat "github.com/go-bumbu/userauth/flow/pat"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
)

type fakeUsers struct{}

func (fakeUsers) GetUser(id string) (userauth.User, error) {
	if id == "u1" {
		return userauth.User{ID: id, LoginID: id + "@example.com", Enabled: true}, nil
	}
	return userauth.User{}, userauth.ErrUserNotFound
}
func (fakeUsers) GetUserByLogin(loginID string) (userauth.User, error) {
	return userauth.User{}, userauth.ErrUserNotFound
}

func TestFlowUnwired(t *testing.T) {
	f := &flowpat.Flow{}
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := f.List(r); err == nil {
		t.Error("unwired flow must error")
	}
	if _, _, err := f.Create(r, "x", nil, nil); err == nil {
		t.Error("unwired flow must error")
	}
	if err := f.Revoke(r, "id"); err == nil {
		t.Error("unwired flow must error")
	}
}

func TestFlowNoIdentity(t *testing.T) {
	svc, err := patsvc.NewService(memory.New(), fakeUsers{}, patsvc.Opts{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	f := &flowpat.Flow{
		Service: svc,
		UserID: func(r *http.Request) (string, error) {
			return "", fmt.Errorf("no session")
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := f.List(r); err != flowpat.ErrNoIdentity {
		t.Errorf("List with no identity: got %v, want ErrNoIdentity", err)
	}
	if _, _, err := f.Create(r, "x", nil, nil); err != flowpat.ErrNoIdentity {
		t.Errorf("Create with no identity: got %v, want ErrNoIdentity", err)
	}
	if err := f.Revoke(r, "id"); err != flowpat.ErrNoIdentity {
		t.Errorf("Revoke with no identity: got %v, want ErrNoIdentity", err)
	}
}

func TestFlowWired(t *testing.T) {
	svc, err := patsvc.NewService(memory.New(), fakeUsers{}, patsvc.Opts{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	f := &flowpat.Flow{
		Service: svc,
		UserID: func(r *http.Request) (string, error) {
			return "u1", nil
		},
	}
	r := httptest.NewRequest("GET", "/", nil)

	// Create
	plaintext, rec, err := f.Create(r, "test", []string{"read"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plaintext == "" || rec.TokenID == "" {
		t.Error("Create returned empty token or record")
	}

	// List
	recs, err := f.List(r)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("List: got %d tokens, want 1", len(recs))
	}

	// Revoke
	if err := f.Revoke(r, rec.TokenID); err != nil {
		t.Errorf("Revoke: %v", err)
	}

	// List again should be empty
	recs, err = f.List(r)
	if err != nil {
		t.Fatalf("List after revoke: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("List after revoke: got %d tokens, want 0", len(recs))
	}
}

func TestFlowCreateWithExpiry(t *testing.T) {
	svc, err := patsvc.NewService(memory.New(), fakeUsers{}, patsvc.Opts{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	f := &flowpat.Flow{
		Service: svc,
		UserID: func(r *http.Request) (string, error) {
			return "u1", nil
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	exp := time.Now().Add(24 * time.Hour)
	_, rec, err := f.Create(r, "expiring", nil, &exp)
	if err != nil {
		t.Fatalf("Create with expiry: %v", err)
	}
	if rec.ExpiresAt == nil {
		t.Error("Create with expiry: ExpiresAt is nil")
	}
}
