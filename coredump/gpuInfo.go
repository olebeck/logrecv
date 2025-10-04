package coredump

type SceDateTime struct {
	Year        uint16
	Month       uint16
	Day         uint16
	Hour        uint16
	Minute      uint16
	Second      uint16
	Microsecond uint32
}

type OffsetValuePair struct {
	Offset uint32
	Value  uint32
}

type OffsetQuadValues struct {
	Offset uint32
	Value1 uint32
	Value2 uint32
	Value3 uint32
	Value4 uint32
}

type GPUInfo struct {
	// Core dump minimum version
	Unk00 uint32

	// Process ID or similar identifier (hardcoded to 10003)
	Unk04 uint32

	// Flags field (ORed together flags)
	Flags uint32

	// DateTime information
	DateTime SceDateTime

	// Hardware information
	SocRevision uint32 // SOC revision & 0x1ffff
	MpFreq      uint32 // MP frequency
	CoreFreq    uint32 // Core frequency
	XbarFreq    uint32 // Crossbar frequency

	// Count fields that determine array sizes
	Unk2C uint32 // Count of something
	Unk30 uint32 // Count for offset-value pairs (sets flags | 1)
	Unk34 uint32 // Count for offset-quad-values (sets flags | 2)
	Unk38 uint32 // Another count (sets flags | 0x24)

	OffsetValuePairs []OffsetValuePair  `bin:"len:Unk30"`
	OffsetQuadValues []OffsetQuadValues `bin:"len:Unk34"`
}
