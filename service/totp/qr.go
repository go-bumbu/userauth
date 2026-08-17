package totp

import (
	"bytes"
	"fmt"
	"image/png"
	"net/url"

	"github.com/pquerna/otp"
)

// QRPNG renders an otpauth:// URI as a square PNG QR code of the given size in
// pixels (a sane default is around 220). It is a convenience over the URI: the
// QR encodes nothing the URI does not, so serving it is as sensitive as showing
// the secret — send it only to the enrolling user, and with caching disabled.
func QRPNG(uri string, size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("totp: QR size must be positive, got %d", size)
	}
	// otp.NewKeyFromURL accepts a lot, including inputs with no otpauth scheme
	// at all, so check that first — a QR code of the wrong string is a support
	// ticket that looks like a working feature
	if u, err := url.Parse(uri); err != nil || u.Scheme != "otpauth" {
		return nil, fmt.Errorf("totp: not an otpauth URI: %q", uri)
	}
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return nil, fmt.Errorf("totp: parse otpauth URI: %w", err)
	}
	img, err := key.Image(size, size)
	if err != nil {
		return nil, fmt.Errorf("totp: render QR: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("totp: encode QR png: %w", err)
	}
	return buf.Bytes(), nil
}
