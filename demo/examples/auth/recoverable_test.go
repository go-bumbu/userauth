package auth

import (
	"crypto/md5" // #nosec G501 -- test mirrors Subsonic's MD5 salted-token protocol
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mintRecoverable hits /new and returns the full token plus its
// username/password split as printed by the endpoint.
func mintRecoverable(t *testing.T, handler http.Handler) (token, username, password string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/new", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("mint token: want 200, got %d", w.Code)
	}
	for _, line := range strings.Split(w.Body.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "token: "):
			token = strings.TrimPrefix(line, "token: ")
		case strings.HasPrefix(line, "username: "):
			username = strings.TrimPrefix(line, "username: ")
		case strings.HasPrefix(line, "password: "):
			password = strings.TrimPrefix(line, "password: ")
		}
	}
	if token == "" || username == "" || password == "" {
		t.Fatalf("could not extract token parts from response: %s", w.Body.String())
	}
	return token, username, password
}

func TestRecoverableSaltedChallenge(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	_, username, password := mintRecoverable(t, handler)

	salt := "c19b2d"
	sum := md5.Sum([]byte(password + salt)) // #nosec G401 -- test mirrors Subsonic's MD5 auth
	challenge := hex.EncodeToString(sum[:])

	q := url.Values{"u": {username}, "t": {challenge}, "s": {salt}}
	req := httptest.NewRequest(http.MethodGet, "/protected?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("salted challenge: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "demo") {
		t.Errorf("salted challenge: body should name the user, got: %s", w.Body.String())
	}
}

func TestRecoverableSaltedChallengeCaseMangledUsername(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	_, username, password := mintRecoverable(t, handler)

	salt := "aa11bb"
	sum := md5.Sum([]byte(password + salt)) // #nosec G401 -- test mirrors Subsonic's MD5 auth
	challenge := hex.EncodeToString(sum[:])

	// token IDs are base36 so they must survive case-mangling clients
	q := url.Values{"u": {strings.ToUpper(username)}, "t": {challenge}, "s": {salt}}
	req := httptest.NewRequest(http.MethodGet, "/protected?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("uppercase username: want 200, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRecoverableWrongChallengeReturns401(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	_, username, _ := mintRecoverable(t, handler)

	q := url.Values{"u": {username}, "t": {strings.Repeat("0", 32)}, "s": {"c19b2d"}}
	req := httptest.NewRequest(http.MethodGet, "/protected?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong challenge: want 401, got %d", w.Code)
	}
}

func TestRecoverableUnknownUsernameReturns401(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	mintRecoverable(t, handler)

	q := url.Values{"u": {"zzzzzzzzzz"}, "t": {strings.Repeat("0", 32)}, "s": {"c19b2d"}}
	req := httptest.NewRequest(http.MethodGet, "/protected?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown username: want 401, got %d", w.Code)
	}
}

func TestRecoverableTokenAlsoWorksAsBearer(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	token, _, _ := mintRecoverable(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Bearer access: want 200, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRecoverableNoCredentialsReturns401(t *testing.T) {
	handler := Recoverable(testLogger(), staticDemoUsers(), testWeb())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no credentials: want 401, got %d", w.Code)
	}
}
