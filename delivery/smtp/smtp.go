package smtp

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"math"
	"net/smtp"
	"os"
	"strings"
	"time"
)

//go:embed default.html
var defaultTemplate embed.FS

// Config holds SMTP connection and template settings.
type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string // literal value, or "@/path/to/file" to read from disk
	From         string
	TemplatePath string // optional; empty = use embedded default
}

// TemplateData is passed to the HTML template.
type TemplateData struct {
	To        string
	Code      string
	ExpiresIn string
}

// Deliverer sends verification codes via SMTP.
type Deliverer struct {
	host     string
	port     int
	username string
	password string
	from     string
	tmpl     *template.Template
}

// New validates config, resolves password, parses template, and returns a Deliverer.
func New(cfg Config) (*Deliverer, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp delivery: host is required")
	}
	if cfg.Port == 0 {
		return nil, fmt.Errorf("smtp delivery: port is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("smtp delivery: from is required")
	}

	password, err := resolvePassword(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("smtp delivery: %w", err)
	}

	tmpl, err := parseTemplate(cfg.TemplatePath)
	if err != nil {
		return nil, fmt.Errorf("smtp delivery: %w", err)
	}

	return &Deliverer{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: password,
		from:     cfg.From,
		tmpl:     tmpl,
	}, nil
}

// Deliver sends an HTML email with the verification code.
func (d *Deliverer) Deliver(_ context.Context, to string, code string, expiresAt time.Time) error {
	msg, err := d.renderMessage(to, code, expiresAt)
	if err != nil {
		return fmt.Errorf("smtp delivery: render: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", d.host, d.port)
	var auth smtp.Auth
	if d.username != "" || d.password != "" {
		auth = smtp.PlainAuth("", d.username, d.password, d.host)
	}

	if err := smtp.SendMail(addr, auth, d.from, []string{to}, msg); err != nil {
		return fmt.Errorf("smtp delivery: send: %w", err)
	}
	return nil
}

// renderMessage builds the full MIME email message.
func (d *Deliverer) renderMessage(to string, code string, expiresAt time.Time) ([]byte, error) {
	data := TemplateData{
		To:        to,
		Code:      code,
		ExpiresIn: formatExpiresIn(time.Until(expiresAt)),
	}

	var htmlBuf bytes.Buffer
	if err := d.tmpl.Execute(&htmlBuf, data); err != nil {
		return nil, err
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", d.from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: Your verification code\r\n")
	fmt.Fprintf(&msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&msg, "\r\n")
	msg.Write(htmlBuf.Bytes())

	return msg.Bytes(), nil
}

// resolvePassword returns the password value. If it starts with "@", the
// remainder is treated as a file path and its contents are read and trimmed.
func resolvePassword(raw string) (string, error) {
	if !strings.HasPrefix(raw, "@") {
		return raw, nil
	}
	path := raw[1:]
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured, not user input
	if err != nil {
		return "", fmt.Errorf("reading password file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// parseTemplate parses the HTML template from path, or uses the embedded default.
func parseTemplate(path string) (*template.Template, error) {
	if path != "" {
		return template.ParseFiles(path)
	}
	return template.ParseFS(defaultTemplate, "default.html")
}

// formatExpiresIn returns a human-readable duration string rounded up to minutes.
func formatExpiresIn(d time.Duration) string {
	minutes := int(math.Ceil(d.Minutes()))
	if minutes < 1 {
		minutes = 1
	}
	if minutes == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}
