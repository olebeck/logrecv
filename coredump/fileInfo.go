package coredump

import (
	"github.com/ghostiam/binstruct"
)

type FileInfoFile struct {
	Unk00      uint32 // 0x00
	FD         int32  // 0x04 - file descriptor
	Attributes uint32 // 0x08
	Flags      uint32 // 0x0C
	PID        int32  // 0x10
	Mode       uint32 // 0x14
	FileOffset uint64 // 0x18
	FileSize   uint64 // 0x20
	Priority   uint32 // 0x28
	Unk1C      uint32 // 0x2C
	Unk20      uint32 // 0x30
	Unk24      uint32 // 0x34
	Unk28      uint32 // 0x38
	Unk2C      uint32 // 0x3C
	Unk30      uint32 // 0x40
	Unk34      uint32 // 0x44

	ResolvedPath string `bin:"AlignedString"`
	Path         string `bin:"AlignedString"`
}

func (FileInfoFile) AlignedString(r binstruct.Reader) (string, error) {
	return AlignedString(r)
}

type FileInfo struct {
	MinVer uint32
	Count  uint32
	Files  []FileInfoFile `bin:"len:Count"`
}
