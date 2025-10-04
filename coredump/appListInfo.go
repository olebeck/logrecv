package coredump

type AppListInfo struct {
	Unk               uint32
	AppID             uint32
	ParentAppID       uint32
	Pid               uint32
	ParentPid         uint32
	TitleID           string `bin:"len:32"`
	BudgetID          uint32
	LaunchMode        uint32
	ProcessAttr       uint32
	MaxOpenedFiles    uint32
	MaxDirectoryLevel uint32
	PathLength        uint32
	Path              string `bin:"len:PathLength"`
}
