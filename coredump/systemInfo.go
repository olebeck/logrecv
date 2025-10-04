package coredump

type SystemInfo struct { // 0x4 + 0x5C
	Unk1          uint32 // min. coredump version
	Unk2          uint32
	Ver1          [4]byte  // version info
	Unk3          uint32   // always 0
	Ver2          [4]byte  // version info
	Unk4          uint32   // always 0
	PSID          [16]byte // ksceSblAimgrGetOpenPsId. zeroed on non-internal
	DeviceType    uint32   // 1 - TOOL, 2 - DEX, 3 - CEX
	ASLRSeed      uint32
	Unk8          uint32 // always 0
	IsDolce       uint32
	HWID          [16]byte // CookedPSID
	AwakeTime     uint64   // SceSysrootForKernel_E20F6FC8 - uptime?
	Unk11         uint32   // ksceSblQafManagerGetQAFlags. 1 if anything set? 0 otherwise?
	VSHBuild      uint32
	GPI           uint32
	AdditionalMem uint32 // SceSysmemForKernel_BC36755F (3.65) / SceSysmemForKernel_4D809B47 (3.60). +109Mb(in bytes), etc
}
