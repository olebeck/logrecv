package coredump

type AppInfo struct {
	MinVer     uint32
	Pad        uint32
	TitleID    string `bin:"len:10"`
	Title      string `bin:"len:128"`
	Version    string `bin:"len:4"`
	SdkVersion [4]uint8
	Unk        [104]byte
}
