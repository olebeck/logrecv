package coredump

type EventFlagInfoEntry struct {
	Unk          uint32
	ID           uint32
	ProcessID    uint32
	Name         string `bin:"len:32"`
	Attributes   uint32
	RefCount     uint32
	InitialValue uint32
	value        uint32
	ThreadCount  uint32
	Entries      []SyncObjectsThread `bin:"len:ThreadCount"`
}

type EventFlagInfo struct {
	MinVer  uint32
	Count   uint32
	Entries []EventFlagInfoEntry `bin:"len:Count"`
}
