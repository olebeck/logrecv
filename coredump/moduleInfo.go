package coredump

type ModuleInfoSegmentinfo struct {
	Size       uint32
	Attributes int32
	BaseAddr   uint32
	MemorySize uint32
	Alignment  uint32
}

// ModuleInfoInfo represents module information
type ModuleInfoInfo struct {
	Size           uint32   // nulled
	ModuleId       uint32   // 04
	SdkVersion     [4]uint8 // 08
	Version        [4]uint8 // 0C
	Type           uint16   // 10
	Flags          uint16   // 12
	Start          uint32   // 14
	ReferenceCount uint32   // 18
	End            uint32   // 1C
	Exit           uint32   // 20
	Name           string   `bin:"len:32"` // 24 - coredump seems to copy just 0x1A (0.945 copied 0x1F), but field size is 0x20
	Status         uint32   // 44
	Fingerprint    uint32   // 48
	SegmentCount   uint32   // 4C

	Segments []ModuleInfoSegmentinfo `bin:"len:SegmentCount"`

	ArmExidxStart uint32
	ArmExidxEnd   uint32
	ArmExtabStart uint32
	ArmExtabEnd   uint32
}

// ModuleInfo represents the container structure for module info
type ModuleInfo struct {
	Unk00 uint32 // coredump minver
	Count uint32 // records count

	// Variable length array of module records
	Modules []ModuleInfoInfo `bin:"len:Count"`
}
