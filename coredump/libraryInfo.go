package coredump

import "github.com/ghostiam/binstruct"

type LibraryInfoExportedFuncs struct {
	Nid     uint32
	Address uint32
}

// LibraryInfoExportedVars represents exported variable information
type LibraryInfoExportedVars struct {
	Nid     uint32
	Address uint32
}

// LibraryInfoInfo represents the main library information structure
type LibraryInfoInfo struct {
	Unk00             uint32 // zeroes
	Id                uint32 // 04
	ModuleId          uint32 // 08
	Attr              uint32 // 0C
	RefCount          uint32 // 10
	ExportedFuncCount uint32 // 14
	ExportedVarCount  uint32 // 18
	TlsOffsetsCount   uint32 // 1C - never encountered non-zero
	ModulesCount      uint32 // 20

	ExportedFuncs   []LibraryInfoExportedFuncs `bin:"len:ExportedFuncCount"`
	ExportedVars    []LibraryInfoExportedVars  `bin:"len:ExportedVarCount"`
	ClientModuleIds []uint32                   `bin:"len:ModulesCount"`
	TlsOffsets      []uint32                   `bin:"len:TlsOffsetsCount"`

	Name string `bin:"AlignedString"`
}

func (LibraryInfoInfo) AlignedString(r binstruct.Reader) (string, error) {
	return AlignedString(r)
}

type LibraryInfo struct {
	MinVer    uint32
	Count     uint32
	Libraries []LibraryInfoInfo `bin:"len:Count"`
}
