package db

import (
	"testing"
	"time"

	"github.com/go-bumbu/userauth/service/verificationcode"
	"github.com/go-bumbu/userauth/service/verificationcode/storetest"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return gdb
}

func newStore(t *testing.T, channel string) *Store {
	t.Helper()
	s, err := New(newDB(t), channel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) verificationcode.CodeStore {
		return newStore(t, "email")
	})
}

func TestNewRejectsAnEmptyChannel(t *testing.T) {
	// an empty channel would make two channels share one row and silently
	// invalidate each other's codes
	if _, err := New(newDB(t), ""); err == nil {
		t.Error("New with an empty channel returned no error")
	}
}

// TestChannelsAreIndependent is the reason the channel column exists: one user
// may have an email code and an SMS code outstanding at the same time.
func TestChannelsAreIndependent(t *testing.T) {
	gdb := newDB(t)
	email, err := New(gdb, "email")
	if err != nil {
		t.Fatalf("New email: %v", err)
	}
	sms, err := New(gdb, "sms")
	if err != nil {
		t.Fatalf("New sms: %v", err)
	}
	future := time.Now().UTC().Add(10 * time.Minute)

	if err := email.StoreCode("u1", "emailhash", future); err != nil {
		t.Fatalf("StoreCode email: %v", err)
	}
	if err := sms.StoreCode("u1", "smshash", future); err != nil {
		t.Fatalf("StoreCode sms: %v", err)
	}

	if ok, err := email.ConsumeCode("u1", "smshash", 5); err != nil || ok {
		t.Fatalf("email store accepted the SMS hash = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := email.ConsumeCode("u1", "emailhash", 5); err != nil || !ok {
		t.Fatalf("email code = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := sms.ConsumeCode("u1", "smshash", 5); err != nil || !ok {
		t.Fatalf("sms code survived the email consume = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestPurgeUserClearsEveryChannel(t *testing.T) {
	gdb := newDB(t)
	email, err := New(gdb, "email")
	if err != nil {
		t.Fatalf("New email: %v", err)
	}
	sms, err := New(gdb, "sms")
	if err != nil {
		t.Fatalf("New sms: %v", err)
	}
	future := time.Now().UTC().Add(10 * time.Minute)
	if err := email.StoreCode("u1", "h1", future); err != nil {
		t.Fatalf("StoreCode email: %v", err)
	}
	if err := sms.StoreCode("u1", "h2", future); err != nil {
		t.Fatalf("StoreCode sms: %v", err)
	}
	if err := sms.StoreCode("u2", "h3", future); err != nil {
		t.Fatalf("StoreCode sms u2: %v", err)
	}

	if err := email.PurgeUser("u1"); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}

	if ok, _ := email.ConsumeCode("u1", "h1", 5); ok {
		t.Error("email code survived PurgeUser")
	}
	if ok, _ := sms.ConsumeCode("u1", "h2", 5); ok {
		t.Error("SMS code survived PurgeUser: one purger must cover every channel")
	}
	if ok, _ := sms.ConsumeCode("u2", "h3", 5); !ok {
		t.Error("purging u1 removed u2's code")
	}
}
