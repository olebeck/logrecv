package coredump

type BudgetSegment struct {
	Unk         uint32
	Base        uint32
	Size        uint32
	FreeSize    uint32
	MinFreeSize uint32
	Units       uint32
	FreeCount   [9]uint32
}

type BudgetPartition struct {
	Unk          uint32
	BudgetID     uint32
	Name         string `bin:"len:32"`
	Type         uint32
	SegmentCount uint32
	Segments     []BudgetSegment `bin:"len:SegmentCount"`
}

type Budget struct {
	Unk            uint32
	BudgetID       uint32
	Name           string `bin:"len:32"`
	PartitionCount uint32
	Partitions     []BudgetPartition `bin:"len:PartitionCount"`
}

type BudgetInfo struct {
	MinVer  uint32
	Count   uint32
	Budgets []Budget `bin:"len:Count"`
}
