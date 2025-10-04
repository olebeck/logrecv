package coredump

type UltQueuePoolInfoInfo struct {
	Size             uint32 // 0x44
	ID               uint32 // addr
	Name             [32]byte
	Attributes       uint32
	MaxDataResources uint32
	NumDataResources uint32
	DataSize         uint32
	MaxQueueObjects  uint32
	NumQueueObjects  uint32
}

type UltQueuePoolInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltQueuePoolInfoInfo `bin:"len:Count"`
	Padding [20]byte               // padding, 5xuint32_t
}
