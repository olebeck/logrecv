package coredump

type HwInfo struct {
	// Minimum coredump version
	Unk1 uint32

	// Hardware identification
	Unk2           uint32
	ProductCode    uint32
	ProductSubcode uint32

	// QAF (Quality Assurance Framework) data
	QafFlags [4]uint32 // 4 uint32 flags
	QafName  [16]byte  // 16-byte QAF name from ksceSblQafManagerGetQafName

	// Reserved/unknown data (always zero?)
	Unk3 [80]byte // 80 bytes of unknown data
}
