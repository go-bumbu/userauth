package memory_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
	"github.com/go-bumbu/userauth/service/pat/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) pat.TokenStore {
		return memory.New()
	})
}
