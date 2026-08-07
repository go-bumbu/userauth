// Package deliver provides the demo's verificationcode.Deliverer
// implementations. The demo cannot send real email or SMS, so codes are
// either stashed for display on the next page (Board) or written to the
// server log (Log). A real deployment wires
// service/verificationcode/deliver/smtp or a custom deliverer instead.
package deliver

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Board remembers the latest plaintext code per recipient so a page can
// display it in place of a delivered message. The verification store only
// keeps a hash, so this is the only place the plaintext survives.
type Board struct {
	mu    sync.Mutex
	codes map[string]string
}

// NewBoard returns an empty Board.
func NewBoard() *Board {
	return &Board{codes: make(map[string]string)}
}

// Deliver implements verificationcode.Deliverer by stashing the code for display.
func (b *Board) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes[to] = code
	return nil
}

// Lookup returns the last code delivered to the recipient, if any.
func (b *Board) Lookup(to string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	code, ok := b.codes[to]
	return code, ok
}

// Clear forgets the recipient's code, e.g. once it has been used.
func (b *Board) Clear(to string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.codes, to)
}

// Log prints verification codes to the server log, for API examples where
// there is no page to show the code on.
type Log struct {
	Logger *slog.Logger
	// Msg labels the log line so codes from different examples are distinguishable.
	Msg string
}

// Deliver implements verificationcode.Deliverer by logging the code.
func (d Log) Deliver(_ context.Context, to string, code string, _ time.Time) error {
	d.Logger.Info(d.Msg, "to", to, "code", code)
	return nil
}
