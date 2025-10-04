package coredump

type MutexInfoMutex struct {
	Unk00           uint32 // zeroes
	Id              uint32 // 04
	ProcessId       uint32 // 08
	Name            string `bin:"len:32"` // 0C
	Attributes      uint32 // 2C
	RefCount        uint32 // 30
	InitialValue    uint32 // 34
	Value           uint32 // 38
	ThreadOwnerId   uint32 // 3C
	ThreadCount     uint32 // 40
	CeilingPriority uint32 // 44 ?

	// Variable length array
	Threads []SyncObjectsThread `bin:"len:ThreadCount"`
}

// MutexInfo represents the container structure for mutex info
type MutexInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of mutex records
	Mutexes []MutexInfoMutex `bin:"len:Count"`
}
