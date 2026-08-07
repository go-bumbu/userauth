package pat_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
)

func TestChainVerifier(t *testing.T) {
	svc, _ := newTestService(t, pat.Opts{})
	plaintext, rec, err := svc.Mint("u1", "api", []string{"read"}, nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	v := svc.ChainVerifier()

	data, ok, err := v.Verify(plaintext)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if data.UserID != "u1" || data.TokenID != rec.TokenID ||
		data.LoginID != "alice@example.com" || data.Name != "api" ||
		len(data.Scopes) != 1 {
		t.Errorf("RequestData mismatch: %+v", data)
	}

	if _, ok, err := v.Verify("garbage"); ok || err != nil {
		t.Errorf("bad token: Verify = %v, %v", ok, err)
	}
}
