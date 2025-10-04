package coredump

type RwlockInfoInfo struct {
	Unk00        uint32   // size? 0x44
	Id           uint32   // 04
	ProcessId    uint32   // 08
	Name         [32]byte // 0C
	Attributes   uint32   // 2C
	RefCount     uint32   // 30
	ReadThreads  uint32   // 34
	WriteThreads uint32   // 38

	// Variable length arrays
	ReadThreadList  []SyncObjectsThread `bin:"len:ReadThreads"`
	WriteThreadList []SyncObjectsThread `bin:"len:WriteThreads"`

	// Commented out fields from original:
	// WriteOwnerId uint32 // 3C
	// LockCount    uint32 // 40
}

// RwlockInfo represents the container structure for read-write lock info
type RwlockInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of rwlock records
	Rwlocks []RwlockInfoInfo `bin:"len:Count"`

	// Padding at the end
	Padding [0x28]byte // 0x28 zero bytes, padding?
}
