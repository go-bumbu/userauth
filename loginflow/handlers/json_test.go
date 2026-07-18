package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-bumbu/userauth"
	"github.com/go-bumbu/userauth/loginflow"
	"github.com/go-bumbu/userauth/loginflow/handlers"
	"github.com/go-bumbu/userauth/loginflow/memory"
	"github.com/go-bumbu/userauth/userstore/staticusers"
	vcmemory "github.com/go-bumbu/userauth/verificationcode/memory"
	"github.com/google/go-cmp/cmp"
	"github.com/pquerna/otp/totp"
)

const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// captureLogin records LoginUser calls instead of creating a real session.
type captureLogin struct {
	userID string
	keep   bool
	calls  int
}

func (l *captureLogin) LoginUser(_ *http.Request, _ http.ResponseWriter, userID string, keep bool) error {
	l.userID = userID
	l.keep = keep
	l.calls++
	return nil
}

// captureDeliverer records the last delivered code instead of sending it.
type captureDeliverer struct {
	code string
}

func (d *captureDeliverer) Deliver(_ context.Context, _ string, code string, _ time.Time) error {
	d.code = code
	return nil
}

func postJSON(t *testing.T, h http.Handler, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) handlers.Response {
	t.Helper()
	var res handlers.Response
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	return res
}

func totpCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func passwordTOTPFixture() (*handlers.JSON, *captureLogin) {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "plain", HashPw: userauth.MustHashPw("plain-pw"), Enabled: true},
		{Id: "careful", HashPw: userauth.MustHashPw("careful-pw"), Enabled: true, TOTPSecret: totpSecret},
		{Id: "gone", HashPw: userauth.MustHashPw("gone-pw"), Enabled: false},
	}}
	session := &captureLogin{}
	j := handlers.NewPasswordTOTP(handlers.PasswordTOTPCfg{
		Users:    users,
		Session:  session,
		Attempts: memory.New(),
		TOTP:     users,
	})
	return j, session
}

func TestPasswordTOTPLogin(t *testing.T) {
	t.Run("password-only user completes at login", func(t *testing.T) {
		j, session := passwordTOTPFixture()
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "plain", Password: "plain-pw", SessionRenew: true})
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		res := decodeResponse(t, w)
		if !res.Done || res.Next != nil {
			t.Fatalf("want done, got %+v", res)
		}
		if session.userID != "plain" || !session.keep {
			t.Errorf("want session for plain with sessionRenew, got %+v", session)
		}
	})

	t.Run("totp user gets next step and completes at verify", func(t *testing.T) {
		j, session := passwordTOTPFixture()
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "careful", Password: "careful-pw"})
		if w.Code != http.StatusOK {
			t.Fatalf("login: want 200, got %d: %s", w.Code, w.Body.String())
		}
		res := decodeResponse(t, w)
		if res.Done {
			t.Fatal("password alone must not complete a TOTP user's login")
		}
		if diff := cmp.Diff([]string{loginflow.MethodTOTP}, res.Next); diff != "" {
			t.Fatalf("next mismatch (-want +got):\n%s", diff)
		}
		if session.calls != 0 {
			t.Fatal("no session before the second factor")
		}

		w = postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "careful", Method: "totp", Code: totpCode(t)})
		if w.Code != http.StatusOK {
			t.Fatalf("verify: want 200, got %d: %s", w.Code, w.Body.String())
		}
		if res := decodeResponse(t, w); !res.Done {
			t.Fatalf("want done after TOTP, got %+v", res)
		}
		if session.userID != "careful" || session.calls != 1 {
			t.Errorf("want one session for careful, got %+v", session)
		}
	})

	t.Run("credential failures are one uniform 401", func(t *testing.T) {
		j, session := passwordTOTPFixture()
		var bodies []string
		for name, p := range map[string]handlers.LoginPayload{
			"wrong password": {User: "plain", Password: "nope"},
			"unknown user":   {User: "ghost", Password: "whatever"},
			"disabled user":  {User: "gone", Password: "gone-pw"},
		} {
			w := postJSON(t, j.LoginHandler(), p)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: want 401, got %d", name, w.Code)
			}
			bodies = append(bodies, w.Body.String())
		}
		for _, b := range bodies[1:] {
			if b != bodies[0] {
				t.Errorf("failure bodies differ: %q vs %q", bodies[0], b)
			}
		}
		if session.calls != 0 {
			t.Error("no session must be created")
		}
	})

	t.Run("totp before password is 401", func(t *testing.T) {
		j, session := passwordTOTPFixture()
		w := postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "careful", Method: "totp", Code: totpCode(t)})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
		if session.calls != 0 {
			t.Error("no session must be created")
		}
	})

	t.Run("wrong totp keeps the attempt open for a retry", func(t *testing.T) {
		j, session := passwordTOTPFixture()
		postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "careful", Password: "careful-pw"})
		w := postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "careful", Method: "totp", Code: "000000"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code: want 401, got %d", w.Code)
		}
		w = postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "careful", Method: "totp", Code: totpCode(t)})
		if w.Code != http.StatusOK {
			t.Fatalf("retry: want 200, got %d", w.Code)
		}
		if session.calls != 1 {
			t.Errorf("want one session after retry, got %d", session.calls)
		}
	})

	t.Run("malformed requests are 400", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		for name, payload := range map[string]any{
			"missing fields": handlers.LoginPayload{User: "plain"},
			"empty body":     struct{}{},
		} {
			w := postJSON(t, j.LoginHandler(), payload)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: want 400, got %d", name, w.Code)
			}
		}
		w := postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "plain", Method: "sms", Code: "1"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("unknown method: want 400, got %d", w.Code)
		}
	})

	t.Run("GET is 405", func(t *testing.T) {
		j, _ := passwordTOTPFixture()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		j.LoginHandler().ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("want 405, got %d", w.Code)
		}
	})

	t.Run("recovery code stands in for totp when configured", func(t *testing.T) {
		users := &staticusers.Users{Users: []staticusers.User{
			{Id: "careful", HashPw: userauth.MustHashPw("pw"), Enabled: true, TOTPSecret: totpSecret},
		}}
		session := &captureLogin{}
		j := handlers.NewPasswordTOTP(handlers.PasswordTOTPCfg{
			Users:    users,
			Session:  session,
			Attempts: memory.New(),
			TOTP:     users,
			Recovery: acceptRecovery{code: "rescue-123"},
		})
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "careful", Password: "pw"})
		res := decodeResponse(t, w)
		want := []string{loginflow.MethodTOTP, loginflow.MethodRecovery}
		if diff := cmp.Diff(want, res.Next); diff != "" {
			t.Fatalf("next mismatch (-want +got):\n%s", diff)
		}
		w = postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "careful", Method: "recovery", Code: "rescue-123"})
		if w.Code != http.StatusOK {
			t.Fatalf("recovery verify: want 200, got %d: %s", w.Code, w.Body.String())
		}
		if !decodeResponse(t, w).Done || session.calls != 1 {
			t.Error("recovery code should complete the login")
		}
	})
}

// acceptRecovery accepts one fixed recovery code (staticusers always says no).
type acceptRecovery struct{ code string }

func (a acceptRecovery) VerifyRecoveryCode(_ string, code string) (bool, error) {
	return code == a.code, nil
}

func emailCodeFixture() (*handlers.JSON, *captureDeliverer, *captureLogin) {
	users := &staticusers.Users{Users: []staticusers.User{
		{Id: "demo@example.com", Enabled: true},
	}}
	deliverer := &captureDeliverer{}
	session := &captureLogin{}
	j := handlers.NewEmailCode(handlers.EmailCodeCfg{
		Users:   users,
		Codes:   userauth.NewVerificationCodeService(vcmemory.New(), userauth.VerificationCodeOpts{}),
		Deliver: deliverer,
		Session: session,
	})
	return j, deliverer, session
}

func TestEmailCodeLogin(t *testing.T) {
	t.Run("happy path: request code then verify", func(t *testing.T) {
		j, deliverer, session := emailCodeFixture()
		w := postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{User: "demo@example.com"})
		if w.Code != http.StatusAccepted {
			t.Fatalf("request: want 202, got %d: %s", w.Code, w.Body.String())
		}
		if deliverer.code == "" {
			t.Fatal("no code delivered")
		}
		w = postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{
			User: "demo@example.com", Method: "email", Code: deliverer.code, SessionRenew: true,
		})
		if w.Code != http.StatusOK {
			t.Fatalf("verify: want 200, got %d: %s", w.Code, w.Body.String())
		}
		if !decodeResponse(t, w).Done {
			t.Fatal("want done")
		}
		if session.userID != "demo@example.com" || !session.keep {
			t.Errorf("want session with sessionRenew, got %+v", session)
		}
	})

	t.Run("request-code responses do not reveal account existence", func(t *testing.T) {
		j, deliverer, _ := emailCodeFixture()
		known := postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{User: "demo@example.com"})
		deliverer.code = ""
		unknown := postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{User: "nobody@example.com"})
		if unknown.Code != known.Code || unknown.Body.String() != known.Body.String() {
			t.Errorf("responses differ: known=%d %q unknown=%d %q",
				known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
		}
		if deliverer.code != "" {
			t.Error("no code must be delivered for an unknown account")
		}
	})

	t.Run("wrong and replayed codes are 401", func(t *testing.T) {
		j, deliverer, session := emailCodeFixture()
		postJSON(t, j.RequestCodeHandler(), handlers.RequestCodePayload{User: "demo@example.com"})
		code := deliverer.code

		w := postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "demo@example.com", Method: "email", Code: "000000"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code: want 401, got %d", w.Code)
		}
		postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "demo@example.com", Method: "email", Code: code})
		w = postJSON(t, j.VerifyHandler(), handlers.VerifyPayload{User: "demo@example.com", Method: "email", Code: code})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("replayed code: want 401, got %d", w.Code)
		}
		if session.calls != 1 {
			t.Errorf("want exactly one session, got %d", session.calls)
		}
	})

	t.Run("password login is 400 on an email-only flow", func(t *testing.T) {
		j, _, _ := emailCodeFixture()
		w := postJSON(t, j.LoginHandler(), handlers.LoginPayload{User: "demo@example.com", Password: "x"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", w.Code)
		}
	})
}
