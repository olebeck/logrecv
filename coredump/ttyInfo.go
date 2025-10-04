package coredump

type TtyInfo struct { // and ttyInfo2
	Unk1   uint32 // min. coredump version
	Unk2   uint32
	Length uint32 // seems to be always 4096
	Buf    [4096]byte
}
