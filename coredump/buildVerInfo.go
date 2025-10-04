package coredump

type BuildVerInfo struct {
	MinVer           uint32
	Unk2             uint32
	SysVer           uint32
	VshVer           uint32
	SysconRev        uint32
	SysBranch        string `bin:"len:64"`
	VshBranch        string `bin:"len:64"`
	SysconBranch     string `bin:"len:64"`
	SdkInternalBuild uint32
	VshBuild         uint32
	Unk3             [0x128]byte
}
