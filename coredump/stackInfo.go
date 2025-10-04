package coredump

type StackInfoInfo struct {
	Unk00           uint32 `bin:"len:4"` // always zeroes?
	ThreadID        uint32 `bin:"len:4"`
	PeakStackUse    uint32 `bin:"len:4"`
	CurrentStackUse uint32 `bin:"len:4"`
}

type StackInfo struct {
	Unk00   uint32          `bin:"len:4"`     // coredump minver
	Count   uint32          `bin:"len:4"`     // records count
	Records []StackInfoInfo `bin:"len:Count"` // count of stackInfo_info follows
}
