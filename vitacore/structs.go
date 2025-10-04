package vitacore

import (
	"fmt"
	"log/slog"
)

type VitaThread struct {
	UID        uint32
	Name       string
	StopReason uint32
	Status     uint16
	PC         uint32
	Regs       *VitaRegs
}

type VitaModuleSegment struct {
	Num   int // seg num (1 based)
	Attr  uint32
	Start uint32
	Size  uint32
	Align uint32
}

type VitaModule struct {
	UID      uint32
	NumSegs  uint32
	Name     string
	Segments []*VitaModuleSegment
}

type VitaRegs struct {
	TID uint32     // Thread ID, links back to VitaThread.UID
	GPR [16]uint32 // General Purpose Registers R0-R15
}

type VitaAddress struct {
	Symbol  string
	Vaddr   uint32
	Module  *VitaModule
	Segment *VitaModuleSegment
	Offset  uint32
}

func (va *VitaAddress) IsLocated() bool {
	return va.Module != nil && va.Segment != nil
}

func (va *VitaAddress) String(elf *ElfParser) string {
	if va.IsLocated() {
		output := fmt.Sprintf("%s: 0x%x (%s@%d + 0x%x", va.Symbol, va.Vaddr,
			va.Module.Name, va.Segment.Num, va.Offset)
		if elf != nil && va.Segment.Num == 1 {
			if addrInfo, err := elf.Addr2Line(va.Offset); err == nil {
				output += fmt.Sprintf(" => %s", addrInfo)
			} else {
				slog.Error("addr2line failed", "offset", va.Offset, "error", err)
			}
		}
		output += ")"
		return output
	}
	return fmt.Sprintf("%s: 0x%x", va.Symbol, va.Vaddr)
}

func (va *VitaAddress) PrintDisassemblyIfAvailable(elf *ElfParser, print func(format string, a ...interface{})) {
	if va.IsLocated() && elf != nil && (va.Segment.Attr&0xF) == 5 {
		vaddrToDisplay := va.Vaddr
		var state string
		if vaddrToDisplay&1 == 0 {
			state = "ARM"
		} else {
			state = "Thumb"
			vaddrToDisplay &= ^uint32(1) // Clear the Thumb bit
		}

		print("")
		print("DISASSEMBLY AROUND %s: 0x%x (%s):", va.Symbol, vaddrToDisplay, state)
		if err := elf.DisassembleAroundAddr(va.Offset); err != nil {
			print("Error getting disassembly: %v", err)
		}
	}
}

type Segment struct {
	Vaddr uint32
	Data  []byte
	Size  uint32
}
