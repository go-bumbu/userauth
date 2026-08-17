package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/demo/internal/demotest"
	"github.com/go-bumbu/userauth/demo/internal/mfa"
	"github.com/go-bumbu/userauth/userstore/userdb"
	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
)

// mountAPI wires the JSON preset the same way the demo router does.
func mountAPI(t *testing.T) (http.Handler, *userdb.Store, mfa.Services) {
	t.Helper()
	users, err := demotest.NewUserStore()
	if err != nil {
		t.Fatal(err)
	}
	mfaSvc, err := mfa.New(demotest.Logger(), users)
	if err != nil {
		t.Fatal(err)
	}
	api := API(demotest.Logger(), users, mfaSvc)
	r := mux.NewRouter()
	r.Path("/api/login").Methods(http.MethodPost).Handler(api.LoginHandler())
	r.Path("/api/login/verify").Methods(http.MethodPost).Handler(api.VerifyHandler())
	return r, users, mfaSvc
}

// enableTOTP enrols the user through the service and returns the secret, the
// way the profile UI does; the service generates it, so the test never writes a
// secret into the store.
func enableTOTP(t *testing.T, mfaSvc mfa.Services, users *userdb.Store, loginID string) string {
	t.Helper()
	usr, err := users.GetUserByLogin(loginID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	enrolment, err := mfaSvc.TOTP.Enroll(usr.ID, loginID)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ok, err := mfaSvc.TOTP.Confirm(usr.ID, code)
	if err != nil || !ok {
		t.Fatalf("confirm enrolment: (%v, %v)", ok, err)
	}
	return enrolment.Secret
}

func postJSON(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

type apiResponse struct {
	Done bool     `json:"done"`
	Next []string `json:"next"`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) apiResponse {
	t.Helper()
	var res apiResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	return res
}

func TestAPILoginPasswordOnly(t *testing.T) {
	handler, _, _ := mountAPI(t)
	w := postJSON(handler, "/api/login", `{"username":"demo","password":"demo"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if res := decode(t, w); !res.Done {
		t.Error("password-only user: want done=true")
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie")
	}
}

func TestAPILoginWrongPassword(t *testing.T) {
	handler, _, _ := mountAPI(t)
	w := postJSON(handler, "/api/login", `{"username":"demo","password":"nope"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie on failed login")
	}
}

func TestAPILoginTOTPSecondFactor(t *testing.T) {
	handler, users, mfaSvc := mountAPI(t)
	secret := enableTOTP(t, mfaSvc, users, "demo")

	// step 1: password accepted, TOTP required
	w := postJSON(handler, "/api/login", `{"username":"demo","password":"demo"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("password step: want 200, got %d; body=%s", w.Code, w.Body.String())
	}
	res := decode(t, w)
	if res.Done {
		t.Fatal("TOTP user: want done=false at the password step")
	}
	if !slices.Contains(res.Next, "totp") {
		t.Fatalf("want \"totp\" in next, got %v", res.Next)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no session cookie should be set at the password step")
	}

	// step 2: verify with a TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w = postJSON(handler, "/api/login/verify", `{"username":"demo","method":"totp","code":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify step: want 200, got %d; body=%s", w.Code, w.Body.String())
	}
	if res := decode(t, w); !res.Done {
		t.Error("verify step: want done=true")
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("expected a session cookie after the second factor")
	}
}
