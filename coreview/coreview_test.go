package coreview

import (
	"logrecv/coredump"
	"logrecv/nids"
	"os"
	"testing"
)

func TestCoreView(t *testing.T) {
	data, err := os.ReadFile("../psp2core-1752243224-0x0001243add-eboot.bin.psp2dmp")
	if err != nil {
		t.Fatal(err)
	}
	cd, err := coredump.ParseCoredump(data)
	if err != nil {
		t.Fatal(err)
	}

	nidDb, err := nids.LoadNids("../db.yml")
	if err != nil {
		t.Fatal(err)
	}
	_ = nidDb

	cv, err := NewCoreView(cd, "../elfs/LEGO00001.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer cv.Close()
	cv.Display()
}
