package coredump

import (
	"os"
	"testing"
)

func TestCoredump(t *testing.T) {
	data, err := os.ReadFile("coredump.psp2dmp")
	if err != nil {
		t.Fatal(err)
	}
	cd, err := ParseCoredump(data)
	if err != nil {
		t.Fatal(err)
	}
	_ = cd
}
