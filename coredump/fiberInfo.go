package coredump

type FiberInfoInfo struct {
	Size        uint32     // 0x00 - zeroes
	Addr        uint32     // 0x04
	Name        string     `bin:"len:32"` // 0x08 - 32 byte name
	FiberState  uint32     // 0x28
	ContextAddr uint32     // 0x2C
	ContextSize uint32     // 0x30
	Entry       uint32     // 0x34
	ThreadID    uint32     // 0x38
	FPSCR       uint32     // 0x3C (note: comment shows 0x38 but structure suggests 0x3C)
	GPRs        [10]uint32 // 0x40 - 10 general purpose registers
	Neon        [8]uint64  // 0x68 - 8 NEON registers (64-bit each)
}

type FiberInfo struct {
	Unk00 uint32          // coredump minver
	Count uint32          // records count
	Infos []FiberInfoInfo `bin:"len:Count"` // count of fiberInfo_info follows
}
