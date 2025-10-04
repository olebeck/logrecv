package coredump

type GameCardInfo struct {
	StructSize  uint32 // 0x40
	Unk04       uint32 // 0x24 (title + this field?)
	Title       [32]byte
	Unk28       uint32 // always 0x00010014. card type?
	CardPresent uint32
	ID          [16]byte
}

type MemoryCardInfo struct {
	StructSize  uint32 // 0x70
	Unk04       uint32 // 0x00000024 (title + this field?)
	Title       [32]byte
	Unk28       uint32 // always 0x00010044. card type?
	CardPresent uint32 // 2C
	// copy of SceMsInfo struct
	Unk30      uint32 // 0,1,2,3,4,5. Only 5 spotted
	Unk34      uint32 // always 0?
	NBytes     uint64 // 38
	NBytes2    uint64 // 40
	SectorSize uint32 // 48 - always 0x200
	Unk4C      uint32 // always 0
	FSOffset   uint32 // 50
	Unk54      uint32
	Unk58      uint32
	Unk5C      uint32
	ID         [16]byte // coredump copies only first part of MCID
}

type SysDeviceInfo struct {
	Unk1       uint32         // min. coredump version
	GameCard   GameCardInfo   // 0x40 bytes
	MemoryCard MemoryCardInfo // 0x70 bytes
}
