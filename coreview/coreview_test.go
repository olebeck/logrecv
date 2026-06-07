package coreview

import (
	"logrecv/coredump"
	"os"
	"testing"
)

func TestCoreView(t *testing.T) {
	data, err := os.ReadFile("../test_crash/psp2core-1773149289-0x00010032bf-eboot.bin.psp2dmp")
	if err != nil {
		t.Fatal(err)
	}
	cd, err := coredump.ParseCoredump(data)
	if err != nil {
		t.Fatal(err)
	}
	cv, err := NewCoreView(cd, "../test_crash/minecraftcpp")
	if err != nil {
		t.Fatal(err)
	}
	defer cv.Close()
	cv.Display()
}
