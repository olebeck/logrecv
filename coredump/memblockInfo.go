package coredump

type MemblockInfoInfo struct {
	Unk00         uint32 // zeroes
	Id            uint32 // 04
	Name          string `bin:"len:32"` // 08
	Type          uint32 // 28
	HeaderAddress uint32 // 2C
	BlockSize     uint32 // 30
	Unk1          uint32 // 34 - zeroes
	Unk2          uint32 // 38 - zeroes
	AllocatedSize uint32 // 3C
	LowSize       uint32 // 40
	HighSize      uint32 // 44
}

// MemBlkInfo represents the container structure for memory block info
type MemblockInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of memory block records
	MemBlocks []MemblockInfoInfo `bin:"len:Count"`
}
