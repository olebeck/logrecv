package coredump

type ThreadInfoThread struct {
	Size              uint32 // size
	ThreadID          uint32 // 04
	Name              string `bin:"len:32"` // 08
	InitialAttributes uint32 // 28
	Attributes        uint32 // 2C
	Status            uint32 // 30 check

	EntryAddress    uint32 // 34
	StackAddressTop uint32 // 38
	StackSize       uint32 // 3C

	StackUsedSize uint32 // 40, zeroes

	ArgSize          uint32 // 44
	ArgBlockBaseAddr uint32 // 48

	InitialPriority     uint32 // 4C
	Priority            uint32 // 50
	InitialAffinityMask uint32 // 54
	AffinityMask        uint32 // 58
	LastCPUID           uint32 // 5C
	WaitStateType       uint32 // 60
	WaitTargetID        uint32 // 64
	ClockRun            uint64 // 68

	Unk70      uint32 // 70, zeroes
	StopReason uint32 // 74
	Unk78      uint32 // 78, zeroes
	Unk7C      uint32 // 7C, zeroes
	Unk80      uint32 // 80, zeroes

	ExitStatus              uint32 // 84
	PreemptedByIntCount     uint32 // 88
	PreemptedByThreadCount  uint32 // 8C
	VoluntarilyReleaseCount uint32 // 90
	ChangeCPUCount          uint32 // 94
	VFPMode                 uint32 // 98
	PC                      uint32 // 9C
	WaitTimeout             uint32 // A0

	// depends on wait_state_type, see waitType
	// looks like maximum 3 uint32_t used
	UnkA4 uint32 // A4
	UnkA8 uint32 // A8
	UnkAC uint32 // AC

	// everything below is zeroed
	UnkB0 uint32 // B0
	UnkB4 uint32 // B4
	UnkB8 uint32 // B8
	UnkBC uint32 // BC
	UnkC0 uint32 // C0
	UnkC4 uint32 // C4
}

type ThreadInfo struct {
	Unk00   uint32
	Count   uint32
	Records []ThreadInfoThread `bin:"len:Count"`
}
