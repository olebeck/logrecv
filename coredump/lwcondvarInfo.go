package coredump

// LwcondvarInfoCondvar represents lightweight condition variable information
type LwcondvarInfoCondvar struct {
	Unk00       uint32   // zeroes
	Id          uint32   // 04
	Name        [32]byte // 08
	Attributes  uint32   // 28
	RefCnt      uint32   // 2C - always set to 0?
	MutexId     uint32   // 30
	ThreadCount uint32   // 34

	// Variable length array
	Threads []SyncObjectsThread `bin:"len:ThreadCount"`

	WorkAddr      uint32 // 38
	MutexWorkAddr uint32 // 3C
}

// LwcondvarInfo represents the container structure for condition variable info
type LwcondvarInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of condition variable records
	Condvars []LwcondvarInfoCondvar `bin:"len:Count"`

	// Padding at the end
	Padding [0x28]byte // 0x28 zero bytes. padding?
}
