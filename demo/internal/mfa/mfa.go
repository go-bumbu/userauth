// Package mfa builds the demo's second-factor services over the database user
// store. Every example that touches TOTP or recovery codes shares one instance,
// because enrolling in the profile example must be usable from the login API —
// two services over the same store but different encryption keys would look
// like corrupted secrets.
package mfa

import (
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/go-bumbu/userauth/service/cipher"
	"github.com/go-bumbu/userauth/service/recoverycodes"
	"github.com/go-bumbu/userauth/service/totp"
	"github.com/go-bumbu/userauth/userstore/userdb/preset"
)

// Issuer is the name authenticator apps show next to the account.
const Issuer = "userauth-demo"

// Services holds the demo's second-factor services.
type Services struct {
	TOTP     *totp.Service
	Recovery *recoverycodes.Service
}

// New wires both services to the given GORM stores. The TOTP encryption key is
// generated per process: key management belongs to the consuming application,
// and an ephemeral key matches the demo's in-memory SQLite (both reset on
// restart). A real deployment loads a persistent key from its secret store.
func New(log *slog.Logger, stores preset.Stores) (Services, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Services{}, fmt.Errorf("generate TOTP encryption key: %w", err)
	}
	secretCipher, err := cipher.NewAESGCM(key, "demo")
	if err != nil {
		return Services{}, err
	}
	totpSvc, err := totp.NewService(stores.TOTP, totp.Opts{
		Issuer: Issuer,
		Cipher: secretCipher,
		Logger: log,
	})
	if err != nil {
		return Services{}, fmt.Errorf("create TOTP service: %w", err)
	}
	recSvc, err := recoverycodes.NewService(stores.Recovery, recoverycodes.Opts{Logger: log})
	if err != nil {
		return Services{}, fmt.Errorf("create recovery code service: %w", err)
	}
	return Services{TOTP: totpSvc, Recovery: recSvc}, nil
}
