package coredump

type ThreadRegInfoInfo struct { // 0x178 size
	Size     uint32 // this struct size. can be 0
	ThreadID uint32 // 04
	R0       uint32 // 08
	R1       uint32 // 0C
	R2       uint32 // 10
	R3       uint32 // 14
	R4       uint32 // 18
	R5       uint32 // 1C
	R6       uint32 // 20
	R7       uint32 // 24
	R8       uint32 // 28
	R9       uint32 // 2C
	R10      uint32 // 30
	R11      uint32 // 34
	R12      uint32 // 38
	SP       uint32 // 3C
	LR       uint32 // 40
	PC       uint32 // 44
	CPSR     uint32 // 48

	FPSCR    uint32 // 4C
	TPIDRURO uint32 // 50

	Neon0    [4]uint32 // 54
	Neon1    [4]uint32 // 64
	Neon2    [4]uint32 // 74
	Neon3    [4]uint32 // 84
	Neon4    [4]uint32 // 94
	Neon5    [4]uint32 // A4
	Neon6    [4]uint32 // B4
	Neon7    [4]uint32 // C4
	Neon8    [4]uint32 // D4
	Neon9    [4]uint32 // E4
	Neon10   [4]uint32 // F4
	Neon11   [4]uint32 // 104
	Neon12   [4]uint32 // 114
	Neon13   [4]uint32 // 124
	Neon14   [4]uint32 // 134
	Neon15   [4]uint32 // 144
	FPEXC    uint32    // 154
	TPIDRURW uint32    // 158

	CPACR uint32 // 15C
	DACR  uint32 // 160

	DBGDSCR uint32 // 164
	IFSR    uint32 // 168
	IFAR    uint32 // 16C
	DFSR    uint32 // 170
	DFAR    uint32 // 174
}

type ThreadRegInfo struct {
	Unk00   uint32
	Count   uint32
	Records []ThreadRegInfoInfo `bin:"len:Count"`
}
