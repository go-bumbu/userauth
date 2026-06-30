package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	initLogger()
	os.Exit(m.Run())
}
