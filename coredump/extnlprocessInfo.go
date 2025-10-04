package coredump

import "github.com/ghostiam/binstruct"

type ExtnlProcessInfoProc struct {
	Zeroes         uint32
	PID            int32
	Budget         uint32
	ProcessAttr    uint32
	Name           string `bin:"len:32"`
	Unk2C          uint32
	CPUAffinity    uint32
	StartEntryAddr uint32
	Fingerprint    uint32
	ParentPID      int32
	Unk44          uint32
	StopReason     uint32
	Unk4C          uint32
	Unk50          uint32
	Unk54          uint32
	Path           string `bin:"AlignedString"`
	ARMExidxStart  uint32
	ARMExidxEnd    uint32
	ARMExtabStart  uint32
	ARMExtabEnd    uint32
}

func (ExtnlProcessInfoProc) AlignedString(r binstruct.Reader) (string, error) {
	return AlignedString(r)
}

type ExtnlProcessInfo struct {
	MinVer uint32
	Count  uint32
	Procs  []ExtnlProcessInfoProc `bin:"len:Count"`
}
