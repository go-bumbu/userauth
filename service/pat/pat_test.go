package pat

import (
	"testing"
)

func TestTokenCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		tokenID string
		secret  string
	}{
		{"default prefix", "pat", "Kx7f3aQ2", "S3cr3tS3cr3tS3cr3tS3cr3tS3cr3tS3cr3tS3cr3t"},
		{"prefix with underscore", "myapp_pat", "AAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := buildToken(tc.prefix, tc.tokenID, tc.secret)
			id, sec, ok := ParseToken(tc.prefix, token)
			if !ok {
				t.Fatalf("ParseToken(%q, %q) not ok", tc.prefix, token)
			}
			if id != tc.tokenID || sec != tc.secret {
				t.Errorf("got (%q, %q), want (%q, %q)", id, sec, tc.tokenID, tc.secret)
			}
		})
	}
}

func TestParseTokenRejects(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		presented string
	}{
		{"empty", "pat", ""},
		{"no underscores", "pat", "garbage"},
		{"one underscore", "pat", "pat_only"},
		{"wrong prefix", "pat", "other_Kx7f3aQ2_secret"},
		{"empty tokenID", "pat", "pat__secret"},
		{"empty secret", "pat", "pat_Kx7f3aQ2_"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := ParseToken(tc.prefix, tc.presented); ok {
				t.Errorf("ParseToken(%q, %q) should reject", tc.prefix, tc.presented)
			}
		})
	}
}

func TestParseTokenExported(t *testing.T) {
	tokenID, secret, ok := ParseToken("aether", "aether_abc123defg_S3CR3T")
	if !ok || tokenID != "abc123defg" || secret != "S3CR3T" {
		t.Errorf("ParseToken = %q, %q, %v", tokenID, secret, ok)
	}
	if _, _, ok := ParseToken("aether", "other_abc123defg_S3CR3T"); ok {
		t.Error("wrong prefix must not parse")
	}
	if _, _, ok := ParseToken("aether", "garbage"); ok {
		t.Error("malformed input must not parse")
	}
}
