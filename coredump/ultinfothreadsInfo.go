package coredump

type UltInfoThreadInfo struct {
	Unk00       uint32 // zeroes. probably size
	ID          uint32 // thread addr
	Name        [32]byte
	State       uint32 // seen: 01, 04
	ThreadEntry uint32 // address
	EntryArg    uint32 // address
	ThreadID    uint32 // zeroes
	ExitCode    uint32 // seen: 0, 0xFFFFFFFF
	FiberAddr   uint32 // fiber info
	Unk7        uint32 // seen: zeroes
}

type UltInfoRuntime struct {
	Unk00         uint32 // zeroes, probably size
	RuntimeID     uint32 // addr
	Name          [32]byte
	WorkerThreads uint32
	MaxUltThreads uint32
	ThreadsCount  uint32
	Threads       []UltInfoThreadInfo `bin:"len:ThreadsCount"`
}

type UltInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltInfoRuntime `bin:"len:Count"`
}
