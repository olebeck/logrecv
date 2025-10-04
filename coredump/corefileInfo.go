package coredump

type CorefileInfo struct {
	Version  uint32
	Internal uint32
	Unk3     [6]uint32
}
