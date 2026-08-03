package smtp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestResolvePassword_Literal(t *testing.T) {
	got, err := resolvePassword("mysecret")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, "mysecret"); diff != "" {
		t.Errorf("unexpected password (-got +want):\n%s", diff)
	}
}

func TestResolvePassword_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePassword("@" + path)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, "file-secret"); diff != "" {
		t.Errorf("unexpected password (-got +want):\n%s", diff)
	}
}

func TestResolvePassword_MissingFile(t *testing.T) {
	_, err := resolvePassword("@/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNew_MissingHost(t *testing.T) {
	_, err := New(Config{Port: 587, From: "a@b.com"})
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestNew_MissingPort(t *testing.T) {
	_, err := New(Config{Host: "smtp.example.com", From: "a@b.com"})
	if err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestNew_MissingFrom(t *testing.T) {
	_, err := New(Config{Host: "smtp.example.com", Port: 587})
	if err == nil {
		t.Fatal("expected error for missing from")
	}
}

func TestNew_ValidConfig(t *testing.T) {
	d, err := New(Config{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("expected non-nil deliverer")
	}
}

func TestNew_CustomTemplate(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "custom.html")
	if err := os.WriteFile(tmplPath, []byte(`<p>Code: {{.Code}}</p>`), 0600); err != nil {
		t.Fatal(err)
	}

	d, err := New(Config{
		Host:         "smtp.example.com",
		Port:         587,
		From:         "noreply@example.com",
		Password:     "secret",
		TemplatePath: tmplPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("expected non-nil deliverer")
	}
}

func TestRenderMessage(t *testing.T) {
	d, err := New(Config{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	msg, err := d.renderMessage("user@example.com", "123456", expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	body := string(msg)
	if !strings.Contains(body, "From: noreply@example.com") {
		t.Errorf("message should contain From header, got:\n%s", body)
	}
	if !strings.Contains(body, "To: user@example.com") {
		t.Errorf("message should contain To header, got:\n%s", body)
	}
	if !strings.Contains(body, "Subject: Your verification code") {
		t.Errorf("message should contain Subject header, got:\n%s", body)
	}
	if !strings.Contains(body, "Content-Type: text/html; charset=UTF-8") {
		t.Errorf("message should contain Content-Type header, got:\n%s", body)
	}
	if !strings.Contains(body, "123456") {
		t.Errorf("message should contain the code, got:\n%s", body)
	}
	if !strings.Contains(body, "15 minutes") {
		t.Errorf("message should contain expiry duration, got:\n%s", body)
	}
}

func TestFormatExpiresIn(t *testing.T) {
	tcs := []struct {
		name string
		dur  time.Duration
		want string
	}{
		{name: "15 minutes", dur: 15 * time.Minute, want: "15 minutes"},
		{name: "1 minute", dur: 1 * time.Minute, want: "1 minute"},
		{name: "90 seconds rounds to 2 minutes", dur: 90 * time.Second, want: "2 minutes"},
		{name: "30 seconds shows 1 minute", dur: 30 * time.Second, want: "1 minute"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := formatExpiresIn(tc.dur)
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("unexpected result (-got +want):\n%s", diff)
			}
		})
	}
}
