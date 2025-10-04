package coredump

type SmplEventInfoInfo struct {
	Unk00       uint32   `bin:"len:4"`  // size? 0x40
	ID          uint32   `bin:"len:4"`  // 04
	ProcessID   uint32   `bin:"len:4"`  // 08
	Name        [32]byte `bin:"len:32"` // 0C
	Attributes  uint32   `bin:"len:4"`  // 2C
	Pattern     uint32   `bin:"len:4"`  // 30
	UserData    uint64   `bin:"len:8"`  // userdata? processid + threadid
	ThreadCount uint32   `bin:"len:4"`
	// thread_count syncObjects_thread follow
}

type SmplEventInfo struct {
	Unk00   uint32              `bin:"len:4"`     // coredump minver
	Count   uint32              `bin:"len:4"`     // records count
	Records []SmplEventInfoInfo `bin:"len:Count"` // count of smplEventInfo_info follows
	Padding [40]byte            `bin:"len:40"`    // 0x28 zero bytes, padding?
}
