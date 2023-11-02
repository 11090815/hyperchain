package main_test

import (
	"os"
	"testing"
)

func Test(t *testing.T) {
	os.MkdirAll("download", os.FileMode(0755))
}
