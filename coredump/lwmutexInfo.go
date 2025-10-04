package coredump

type LwMutexInfoMutex struct {
	Unk00         uint32 // zeroes
	Id            uint32 // 04
	Name          string `bin:"len:32"` // 08
	Attributes    uint32 // 28
	WorkAddress   uint32 // 2C
	InitialValue  uint32 // 30
	Value         uint32 // 34
	ThreadOwnerId uint32 // 38
	ThreadCount   uint32 // 3C

	// Variable length array
	Threads []SyncObjectsThread `bin:"len:ThreadCount"`
}

// LwMutexInfo represents the container structure for mutex info
type LwMutexInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of mutex records
	Mutexes []LwMutexInfoMutex `bin:"len:Count"`
}
