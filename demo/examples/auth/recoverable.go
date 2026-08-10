package auth

import (
	"crypto/md5" // #nosec G501 -- demo mirrors Subsonic's MD5 salted-token protocol
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/demo/web"
	patsvc "github.com/go-bumbu/userauth/service/pat"
	patmemory "github.com/go-bumbu/userauth/service/pat/store/memory"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// Recoverable demonstrates PAT recoverable storage (the "user+token" mode):
// /new mints a Recoverable token for the demo user and splits it via
// ParseToken into a virtual username (the token ID) and password (the
// secret); /protected authenticates a Subsonic-style salted challenge —
// u=<tokenID>, t=md5(secret+salt), s=<salt> — via VerifyMatch, where the
// server never sees the secret on the wire. The same token also still works
// whole as a Bearer apiKey. The AES key is generated at startup (demo only —
// real applications load it from configuration or a KMS; key management is
// the consumer's concern).
func Recoverable(log *slog.Logger, users userauth.UserGetter, rnd *web.Renderer) http.Handler {
	cipher, err := patsvc.NewAESGCMCipher(securecookie.GenerateRandomKey(32), "demo-key-1")
	if err != nil {
		panic(fmt.Errorf("recoverable demo: cipher: %w", err))
	}
	pats, err := patsvc.NewService(patmemory.New(), users, patsvc.Opts{Cipher: cipher, Logger: log})
	if err != nil {
		panic(fmt.Errorf("recoverable demo: %w", err))
	}

	r := mux.NewRouter()
	r.Path("/new").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		plaintext, _, err := pats.Mint("demo", "subsonic demo token", nil, nil, patsvc.Recoverable)
		if err != nil {
			http.Error(w, "could not mint token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenID, secret, ok := patsvc.ParseToken("pat", plaintext)
		if !ok {
			http.Error(w, "could not parse minted token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, `recoverable token minted for user 'demo'

token: %s
username: %s
password: %s

Subsonic-style challenge login (t = md5(password + salt), secret never on the wire):
  salt=$(openssl rand -hex 6)
  t=$(printf '%%s%%s' '%s' "$salt" | md5sum | awk '{print $1}')
  curl "http://localhost:8085/rectoken/protected?u=%s&t=$t&s=$salt"

the same token still works whole as an apiKey:
  curl -H "Authorization: Bearer %s" http://localhost:8085/rectoken/protected
`, plaintext, tokenID, secret, secret, tokenID, plaintext)
	})

	r.Path("/protected").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		if u, t, s := q.Get("u"), q.Get("t"), q.Get("s"); u != "" && t != "" && s != "" {
			want := []byte(strings.ToLower(t))
			info, ok, err := pats.VerifyMatch(u, func(secret string) bool {
				sum := md5.Sum([]byte(secret + s)) // #nosec G401 -- demo mirrors Subsonic's MD5 salted-token protocol
				got := []byte(hex.EncodeToString(sum[:]))
				return subtle.ConstantTimeCompare(got, want) == 1
			})
			// ErrNotRecoverable is a credential failure to unauthenticated
			// callers: surfacing it would reveal that the token ID exists.
			if err != nil && !errors.Is(err, patsvc.ErrNotRecoverable) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if err == nil && ok {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = fmt.Fprintf(w, "authenticated as %s via salted challenge for token %q\n", info.UserID, info.Name)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if ah := req.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			info, ok, err := pats.Verify(strings.TrimPrefix(ah, "Bearer "))
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if ok {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = fmt.Fprintf(w, "authenticated as %s via whole token %q\n", info.UserID, info.Name)
				return
			}
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	return r
}
