package coredump

type CallbackInfoEntry struct {
	Size         uint32
	ID           uint32
	ProcessID    uint32
	ThreadID     uint32
	Name         string `bin:"len:32"`
	Attributes   uint32
	RefCount     uint32
	CallbackFunc uint32
	ArgAddr      uint32
	NotifyCount  uint32
	NotifyArg    uint32
}

type CallbackInfo struct {
	MinVer  uint32
	Count   uint32
	Entries []CallbackInfoEntry `bin:"len:Count"`
}
