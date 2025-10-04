package coredump

type UltMutexInfoInfo struct {
	Unk00              uint32 // zeroes, probably size
	ID                 uint32 // addr
	Name               [32]byte
	Attributes         uint32
	QueuePoolID        uint32 // addr
	LockStatus         uint32
	RecursiveLockCount uint32
	ThreadOwnerID      uint32
	NumWaitThreads     uint32
	ThreadIDs          []uint32 `bin:"len:NumWaitThreads"`
}

type UltMutexInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltMutexInfoInfo `bin:"len:Count"`
}
