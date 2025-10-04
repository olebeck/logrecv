package coredump

type SemaphoreInfoSemaphore struct {
	Unk00        uint32   // zeroes
	Id           uint32   // 04
	ProcessId    uint32   // 08
	Name         [32]byte // 0C
	Attributes   uint32   // 2C
	RefCount     uint32   // 30
	InitialValue uint32   // 34
	Value        uint32   // 38
	MaxValue     uint32   // 3C
	ThreadCount  uint32   // 40

	// Variable length array
	Threads []SyncObjectsThread `bin:"len:ThreadCount"`
}

// SemaphoreInfo represents the container structure for semaphore info
type SemaphoreInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of semaphore records
	Semaphores []SemaphoreInfoSemaphore `bin:"len:Count"`
}
