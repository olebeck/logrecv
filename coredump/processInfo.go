package coredump

import "github.com/ghostiam/binstruct"

type ProcessInfo struct {
	Unk0           uint32   // min. coredump version
	Unk4           uint32   // zeroes // 0
	Pid            int32    // 4
	ProcessAttr    uint32   // PROCESS_ATTR_* // 8
	TitleId        [32]byte // contains titleid in first 10 bytes // 0xC
	Unk2C          uint32   // seems to be always zero // 2C
	CpuAffinity    uint32   // 30
	StartEntryAddr uint32   // 34
	Fingerprint    uint32   // 38
	ParentPid      int32    // 3C
	Unk40          uint32   // zeroes
	StopReason     uint32   // 44
	AdditionalId   uint32   // 48 // not set - zeroes
	Unk4C          uint32   // zeroes
	Unk50          uint32   // zeroes
	Path           string   `bin:"AlignedString"`

	ArmExidxStart uint32
	ArmExidxEnd   uint32
	ArmExtabStart uint32
	ArmExtabEnd   uint32
	Time          uint64 // process time in microseconds
}

func (ProcessInfo) AlignedString(r binstruct.Reader) (string, error) {
	return AlignedString(r)
}
