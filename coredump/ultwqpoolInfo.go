package coredump

type UltWQPoolInfoInfo struct {
	Size          uint32 // 0x44
	ID            uint32 // addr
	Name          [32]byte
	MaxNumWaiters uint32
	NumWaiters    uint32
	MaxSyncObjs   uint32
	NumSyncObjs   uint32
}

type UltWQPoolInfo struct {
	Unk00   uint32
	Count   uint32
	Records []UltWQPoolInfoInfo `bin:"len:Count"`
	Padding [20]byte            // padding, 5xuint32_t
}
