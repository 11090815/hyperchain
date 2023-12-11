package msp

import "testing"

func TestInvalidAdminNodeOU(t *testing.T) {
	_ = getLocalMSP(t, "testdata/nodeous1")
}
