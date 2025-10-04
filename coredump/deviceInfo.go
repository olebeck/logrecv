package coredump

type DeviceInfo struct {
	MinVer                 uint32
	Unk                    uint32
	AudioExclusiveOwnerPID uint32
	AudioMainOutOwnerPID   uint32
	AudioBgmOutOwnerPID    uint32
	AudioVoiceOutOwnerPID  uint32
	AudioInOwnerPID        uint32

	DisplaybackPortOwnerPID       uint32
	InputDeviceOwnerPID           uint32
	BluetoothControllerOwnerAppID uint32
	ShellPID                      uint32
	ActiveAppAppID                uint32
	DisplayOwnerPID0              uint32
	DisplayOwnerPID1              uint32
	SystemChatOwnerAppID          uint32
	BackRenderPortOwnerAppID      uint32
	RenderPidsCount               uint32
	RenderPids                    []uint32 `bin:"len:RenderPidsCount"`
	TouchPidsCount                uint32
	TouchPids                     []uint32 `bin:"len:TouchPidsCount"`
	Zeros                         [30]uint32
}
