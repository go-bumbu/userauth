package memory_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/verificationcode"
	"github.com/go-bumbu/userauth/service/verificationcode/store/memory"
	"github.com/go-bumbu/userauth/service/verificationcode/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) verificationcode.CodeStore {
		return memory.New()
	})
}
