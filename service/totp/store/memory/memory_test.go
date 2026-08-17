package memory_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/totp"
	"github.com/go-bumbu/userauth/service/totp/store/memory"
	"github.com/go-bumbu/userauth/service/totp/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) totp.Store {
		return memory.New()
	})
}
