package coredump

type SyncObjectsThread struct {
	ProcessID uint32
	ThreadID  uint32
}

type CondVarInfoEntry struct {
	Size        uint32
	ID          uint32
	ProcessID   uint32
	Name        string `bin:"len:32"`
	Attributes  uint32
	RefCount    uint32
	ThreadID    uint32
	ThreadCount uint32
	Entries     []SyncObjectsThread `bin:"len:ThreadCount"`
}

type CondVarInfo struct {
	MinVer  uint32
	Count   uint32
	Entries []CondVarInfoEntry `bin:"len:Count"`
}
