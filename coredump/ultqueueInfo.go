package coredump

type UltQueueInfoInfo struct {
	Size            uint32 // 0x44
	ID              uint32 // addr
	Name            [32]byte
	Attributes      uint32
	WqPoolID        uint32
	QueueDataPoolID uint32
	DataSize        uint32
	NumPushThreads  uint32
	NumPopThreads   uint32
	DataCount       uint32
	PushThreadIDs   []uint32 `bin:"len:NumPushThreads"`
	PopThreadIDs    []uint32 `bin:"len:NumPopThreads"`
	Data            [][]byte `bin:"len:DataCount,[len:DataSize]"`
}

type UltQueueInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltQueueInfoInfo `bin:"len:Count"`
	Padding [20]byte           // padding, 5xuint32_t
}
