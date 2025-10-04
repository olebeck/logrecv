package coredump

type UltSemaInfoInfo struct {
	Unk00               uint32 // zeroes, probably size
	ID                  uint32 // addr
	Name                [32]byte
	Attributes          uint32
	QueuePoolID         uint32 // addr
	NumCurrentResources uint32
	NumWaitThreads      uint32
	ThreadIDs           []uint32 `bin:"len:NumWaitThreads"`
}

type UltSemaInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltSemaInfoInfo `bin:"len:Count"`
}
