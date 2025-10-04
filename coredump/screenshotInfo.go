package coredump

type ScreenshotInfo struct {
	Unk1   uint32 // min. coredump version
	Unk2   uint32
	Unk3   uint32 // maybe vsync count?
	Width  uint32
	Height uint32
	Unk4   uint32
	Data   []uint32 `bin:"len:Width*Height*4"`
}
