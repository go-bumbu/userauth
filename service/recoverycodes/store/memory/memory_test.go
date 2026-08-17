package memory_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/recoverycodes"
	"github.com/go-bumbu/userauth/service/recoverycodes/store/memory"
	"github.com/go-bumbu/userauth/service/recoverycodes/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) recoverycodes.Store {
		return memory.New()
	})
}
