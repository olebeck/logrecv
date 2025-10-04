package vitacore

// Stop reasons for threads.
var StopReasons = map[uint32]string{
	0x0:     "No reason",
	0x30002: "Undefined instruction exception",
	0x30003: "Prefetch abort exception",
	0x30004: "Data abort exception",
	0x60080: "Division by zero",
}

// Thread status values.
var ThreadStatus = map[uint16]string{
	1:  "Running",
	8:  "Waiting",
	16: "Not started",
}

// Memory segment attributes.
var SegmentAttributes = map[uint32]string{
	5: "RX", // Read + Execute
	6: "RW", // Read + Write
}

// Common ARM register names.
var RegNames = map[int]string{
	13: "SP", // Stack Pointer
	14: "LR", // Link Register
	15: "PC", // Program Counter
}
