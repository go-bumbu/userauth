package storetest_test

import (
	"testing"

	"github.com/go-bumbu/userauth/service/pat"
	"github.com/go-bumbu/userauth/service/pat/store/memory"
	"github.com/go-bumbu/userauth/service/pat/storetest"
)

// TestRunAgainstMemory exercises the conformance suite itself; the memory
// store is the reference implementation.
func TestRunAgainstMemory(t *testing.T) {
	storetest.Run(t, func(t *testing.T) pat.TokenStore {
		return memory.New()
	})
}
