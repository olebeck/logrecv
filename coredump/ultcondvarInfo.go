package coredump

type UltCondvarInfoInfo struct {
	Unk00          uint32 // zeroes, probably size
	ID             uint32 // addr
	Name           [32]byte
	Attributes     uint32
	MutexID        uint32
	NumWaitThreads uint32
	ThreadIDs      []uint32 `bin:"len:NumWaitThreads"`
}

type UltCondvarInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltCondvarInfoInfo `bin:"len:Count"`
}
