package coredump

type EventLogInfoEvent struct {
	Size        uint32
	AppNameSize uint32
	AppName     string `bin:"len:12"` // 0xC bytes, hardcoded in crashdump
	EvID        uint16 // event facility id/type. 10001 - Processmgr, 20000 - shell, 20001 - WlanBt
	Type        uint16 // event type
	PID         uint32
	ThreadGUID  uint32    // return of SceSysrootForKernel_D441DC34
	Rsvd        [4]uint32 // reserved
	EventTime   uint64
	Unk3        uint32 // param5 of 0x912CF2BA (param3 of 0x95B38C6C). 0 from Processmgr, shell and WlanBt
	DataSize    uint32 // 0x1C - processmgr, 0x54 and 0x4 - shell, 0x4 - WlanBt
	// Variable data follows based on DataSize and Type
	Data []byte `bin:"len:DataSize"`
}

type EventLogInfo struct {
	MinVer     uint32
	Unk04      uint32 // zeroes
	EventCount uint32
	Events     []EventLogInfoEvent `bin:"len:EventCount"`
}
