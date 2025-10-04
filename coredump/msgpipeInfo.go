package coredump

type MsgpipeInfoPipe struct {
	Unk00              uint32 // ?? 0x05
	Id                 uint32 // 04
	ProcessId          uint32 // 08
	Name               string `bin:"len:32"` // 0C
	Attributes         uint32 // 2C
	RefCount           uint32 // 30
	BufferByteSize     uint32 // 34
	FreeBufferByteSize uint32 // 38
	SendThreadCount    uint32 // 3C
	RecvThreadCount    uint32 // 40

	// Variable length arrays
	SendThreads []SyncObjectsThread `bin:"len:SendThreadCount"`
	RecvThreads []SyncObjectsThread `bin:"len:RecvThreadCount"`

	EventPattern uint32
	UserData     uint64
}

// MsgpipeInfo represents the container structure for message pipe info
type MsgpipeInfo struct {
	MinVer uint32 // coredump minver
	Count  uint32 // records count

	// Variable length array of message pipe records
	Msgpipes []MsgpipeInfoPipe `bin:"len:Count"`
}
