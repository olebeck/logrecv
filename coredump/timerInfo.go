package coredump

type TimerInfoInfo struct {
	Unk00        uint32              // size 0x70
	ID           uint32              // 04
	ProcessID    uint32              // 08
	Name         [32]byte            // 0C
	Attributes   uint32              // 2C
	RefCnt       uint32              // 30
	ActiveState  uint32              // 34
	TimeBase     uint64              // 38
	TimeCurrent  uint64              // 40
	TimeSchedule uint64              // 48
	TimeInterval uint64              // 50
	EventType    uint32              // 58
	Repeat       uint32              // 5C
	ThreadCnt    uint32              // 60
	Threads      []SyncObjectsThread `bin:"len:ThreadCnt"`
	EventPattern uint32
	ThreadID     uint32
	Unk          uint32
}

type TimerInfo struct {
	Unk00   uint32
	Count   uint32
	Records []TimerInfoInfo `bin:"len:Count"`
	Padding [40]byte        // 0x28 zero bytes, padding?
}
