package coredump

type UltRWLockInfoInfo struct {
	Size              uint32 // 0x44
	ID                uint32 // addr
	Name              [32]byte
	Attributes        uint32
	QueuePoolID       uint32 // addr
	LockStatus        uint32
	NumLockingReaders uint32
	NumReadThreads    uint32
	NumWriteThreads   uint32
	ReadThreadIDs     []uint32 `bin:"len:NumReadThreads"`
	WriteThreadIDs    []uint32 `bin:"len:NumWriteThreads"`
	ThreadOwnerID     uint32
}

type UltRWLockInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltRWLockInfoInfo `bin:"len:Count"`
}
