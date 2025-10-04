package coreview

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"logrecv/coredump"
	"os"
	"os/exec"
	"slices"
	"strings"
	"unicode"

	"github.com/ianlancetaylor/demangle"
	"github.com/sirupsen/logrus"
)

var armRegNames = []string{
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
}

var stopReasons = map[uint32]string{
	0:       "No reason",
	0x30002: "Undefined instruction exception",
	0x30003: "Prefetch abort exception",
	0x30004: "Data abort exception",
	0x60080: "Division by zero",
}

func stopReasonString(v uint32) string {
	reason, ok := stopReasons[v]
	if !ok {
		return "invalid"
	}
	return reason
}

func cstr(a string) string {
	idx := strings.IndexRune(a, '\x00')
	if idx == -1 {
		return a
	}
	return a[:idx]
}

type CoreView struct {
	cd         *coredump.Coredump
	elf        *elf.File
	syms       []elf.Symbol
	cfiEntries []CFIEntry

	textSection    *elf.Section
	textSectionIdx int
	dataSection    *elf.Section
	dataSectionIdx int

	textBase    uint32
	elfFilename string
}

func NewCoreView(cd *coredump.Coredump, elfFilename string) (*CoreView, error) {
	cv := &CoreView{
		cd:          cd,
		elfFilename: elfFilename,
	}
	var err error
	cv.elf, err = elf.Open(elfFilename)
	if err != nil {
		return nil, err
	}
	for _, prog := range cv.elf.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if prog.Flags&elf.PF_X != 0 {
			cv.textBase = uint32(prog.Vaddr)
		}
	}

	for i, section := range cv.elf.Sections {
		if section.Name == ".text" {
			cv.textSection = section
			cv.textSectionIdx = i
		}
		if section.Name == ".data" {
			cv.dataSection = section
			cv.dataSectionIdx = i
		}
	}

	syms, err := cv.elf.Symbols()
	if err != nil {
		return nil, err
	}

	for _, sym := range syms {
		if sym.Value < cv.textSection.Addr {
			continue
		}
		cv.syms = append(cv.syms, sym)
	}
	slices.SortFunc(cv.syms, func(a, b elf.Symbol) int {
		return int(a.Value) - int(b.Value)
	})

	debugFrame := cv.elf.Section(".debug_frame")
	if debugFrame != nil {
		debugFrameData, err := debugFrame.Data()
		if err != nil {
			return nil, err
		}

		cv.cfiEntries, err = parseCFIEntries(debugFrameData)
		if err != nil {
			return nil, err
		}
	}

	return cv, nil
}

func (cv *CoreView) Close() error {
	if cv.elf != nil {
		cv.elf.Close()
	}
	return nil
}

func (cv *CoreView) Display() {
	crashThreadID, err := cv.cd.GetCrashThreadID()
	if err != nil {
		logrus.Error(err)
		return
	}

	cv.displayThreads()
	cv.displayDisassembly(crashThreadID)
	cv.displayRegisters(crashThreadID)
	cv.displayStackContents(crashThreadID)
	cv.displayStacktrace(crashThreadID)
}

func (cv *CoreView) displayThreads() {
	fmt.Println("\n=== THREADS ===")
	for _, threadInfo := range cv.cd.ThreadInfo.Records {
		fmt.Printf("  %s\n", threadInfo.Name)
		fmt.Printf("    ID: 0x%08x\n", threadInfo.ThreadID)
		fmt.Printf("    Stop reason: 0x%x (%s)\n", threadInfo.StopReason, stopReasonString(threadInfo.StopReason))
		fmt.Printf("    PC: 0x%x %s\n", threadInfo.PC, cv.getFunctionName(threadInfo.PC))
	}
}

type regVal struct {
	Name  string
	Value uint32
}

func (cv *CoreView) displayRegisters(threadID uint32) {
	fmt.Println("\n=== REGISTERS ===")
	registers := cv.cd.GetThreadRegisters(threadID)

	for _, reg := range []regVal{
		{"R0", registers.R0},
		{"R1", registers.R1},
		{"R2", registers.R2},
		{"R3", registers.R3},
		{"R4", registers.R4},
		{"R5", registers.R5},
		{"R6", registers.R6},
		{"R7", registers.R7},
		{"R8", registers.R8},
		{"R9", registers.R9},
		{"R10", registers.R10},
		{"R11", registers.R11},
		{"R12", registers.R12},
		{"SP", registers.SP},
		{"PC", registers.PC},
		{"LR", registers.LR},
	} {
		fmt.Printf("%-3s: 0x%x", reg.Name, reg.Value)
		if reg.Name == "LR" || reg.Name == "PC" {
			fmt.Printf(" %s", cv.getFunctionName(reg.Value))
		}
		fmt.Println()
	}
}

func (cv *CoreView) displayStackContents(threadID uint32) {
	sp := cv.cd.GetThreadRegisters(threadID).SP
	fmt.Println("\n=== STACK CONTENTS ===")
	fmt.Printf("Stack Pointer: 0x%08x\n", sp)

	stackSize := 256
	stackData := cv.cd.ReadVaddr(sp, stackSize)
	if len(stackData) == 0 {
		logrus.Error("Could not read stack data")
		return
	}

	for i := 0; i < len(stackData); i += 16 {
		end := min(i+16, len(stackData))

		fmt.Printf("0x%08x: ", sp+uint32(i))

		for j := i; j < end; j += 4 {
			if j+4 <= len(stackData) {
				word := binary.LittleEndian.Uint32(stackData[j : j+4])
				fmt.Printf("%08x ", word)
			}
		}

		fmt.Print(" |")
		for j := i; j < end; j++ {
			if stackData[j] >= 32 && stackData[j] <= 126 {
				fmt.Printf("%c", stackData[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Print("|")

		for j := i; j < end && j+4 <= len(stackData); j += 4 {
			word := binary.LittleEndian.Uint32(stackData[j : j+4])
			if location := cv.getAddressLocation(word); location != "" {
				fmt.Printf("  [+%d: %s]", j-i, location)
				break
			}
		}
		fmt.Println()
	}
	fmt.Println()
}

func (cv *CoreView) ReadUint32(addr uint32) (uint32, error) {
	data := cv.cd.ReadVaddr(addr, 4)
	if len(data) == 0 {
		return 0, io.EOF
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (cv *CoreView) ReadBytes(addr uint32, size int) ([]byte, error) {
	data := cv.cd.ReadVaddr(addr, size)
	if data == nil {
		return nil, io.EOF
	}
	return data, nil
}

func (cv *CoreView) displayStacktrace(threadID uint32) {
	fmt.Println("\n=== STACK TRACE ===")
	regs := cv.cd.GetThreadRegisters(threadID)
	if cv.cfiEntries == nil {
		fmt.Printf("No DWARF\n")
		return
	}

	frames, err := UnwindStack(cv.cfiEntries, regs, cv, 10)
	if err != nil {
		logrus.Fatal(err)
	}

	for i, frame := range frames {
		fmt.Printf("Frame %d:\n", i)
		fmt.Printf("  PC: 0x%08x %s", frame.PC, cv.getFunctionName(frame.PC))
		if frame.IsThumb {
			fmt.Printf(" (Thumb)")
		} else {
			fmt.Printf(" (ARM)")
		}
		fmt.Printf("\n")
		fmt.Printf("  SP: 0x%08x\n", frame.SP)
		fmt.Printf("  LR: 0x%08x %s\n", frame.LR, cv.getFunctionName(frame.LR))

		for _, reg := range []regVal{
			{"R0", frame.Registers.R0},
			{"R1", frame.Registers.R1},
			{"R2", frame.Registers.R2},
			{"R3", frame.Registers.R3},
		} {
			fmt.Printf("  %-3s: 0x%x\n", reg.Name, reg.Value)
		}

		cv.showDisassembly(frame.PC, fmt.Sprintf("Frame %d", i), "  ")
	}
}

func (cv *CoreView) displayDisassembly(threadID uint32) {
	regs := cv.cd.GetThreadRegisters(threadID)

	fmt.Println("\n=== PC DISASSEMBLY ===")
	fmt.Printf("PC: 0x%08x %s\n", regs.PC, cv.getFunctionName(regs.PC))
	cv.showDisassembly(regs.PC, "PC", "")
	fmt.Println()

	fmt.Println("\n=== LR DISASSEMBLY ===")
	fmt.Printf("LR: 0x%08x %s\n", regs.LR, cv.getFunctionName(regs.LR))
	cv.showDisassembly(regs.LR, "LR", "")
	fmt.Println()
}

func (cv *CoreView) getAddressLocation(vaddr uint32) string {
	module, _ := cv.cd.GetModuleInfo(vaddr)
	if module != nil {
		return cv.getFunctionName(vaddr)
	}
	return ""
}

func (cv *CoreView) vaddrToElfaddr(vaddr uint32) uint32 {
	module, segment := cv.cd.GetModuleInfo(vaddr)
	_ = module
	relAddr := vaddr - segment.BaseAddr
	elfAddr := relAddr + cv.textBase
	return elfAddr
}

func (cv *CoreView) getFunctionName(vaddr uint32) string {
	module, segment := cv.cd.GetModuleInfo(vaddr)
	if module == nil {
		return "(unknown module)"
	}

	out := ""
	out += fmt.Sprintf("(%s)", cstr(module.Name))

	relAddr := vaddr - segment.BaseAddr
	out += fmt.Sprintf("+0x%x", relAddr)
	if module.Fingerprint == cv.cd.ProcessInfo.Fingerprint {
		if symbol := cv.getSymbolFromEboot(relAddr); symbol != "" {
			out += " " + symbol
		}
	}

	return out
}

// returns the symbol in the main eboot that is at vaddr
func (cv *CoreView) getSymbolFromEboot(relAddr uint32) string {
	elfAddr := relAddr + cv.textBase

	for _, sym := range cv.syms {
		size := max(sym.Size, 8)
		if uint32(sym.Value) <= elfAddr && uint32(sym.Value+size) >= elfAddr {
			name, err := demangle.ToString(sym.Name)
			if err != nil {
				return sym.Name
			}
			return name
		}
	}
	return ""

	/*
		cmd := exec.Command("arm-vita-eabi-addr2line", "-e", cv.elfFilename, "-f", "-C", fmt.Sprintf("0x%x", elfAddr))
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) >= 1 && lines[0] != "??" {
			symbol := lines[0]
			// Clean up the symbol name
			if idx := strings.Index(symbol, "("); idx != -1 {
				symbol = symbol[:idx]
			}
			return symbol
		}
		return ""
	*/
}

func (cv *CoreView) showDisassembly(vaddr uint32, label, indent string) error {
	fmt.Printf(indent+"Disassembly around %s (0x%08x):\n", label, vaddr)

	module, segment := cv.cd.GetModuleInfo(vaddr)
	if module == nil {
		fmt.Printf(indent+"unknown module at 0x%x\n", vaddr)
		return nil
	}
	if module.Fingerprint != cv.cd.ProcessInfo.Fingerprint {
		fmt.Print(indent + "not in main elf\n")
		return nil
	}
	relAddr := vaddr - segment.BaseAddr
	elfAddr := relAddr + cv.textBase

	startAddr := elfAddr - 16
	size := 32

	cmd := exec.Command("arm-vita-eabi-objdump",
		"-d", "-S",
		"--start-address", fmt.Sprintf("0x%08x", startAddr),
		"--stop-address", fmt.Sprintf("0x%08x", startAddr+uint32(size)),
		cv.elfFilename,
	)
	b := bytes.NewBuffer(nil)
	cmd.Stdout = b
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	vaddrHex := fmt.Sprintf("%08x", elfAddr)
	indent += "  "
	for {
		line, err := b.ReadString('\n')
		if err == io.EOF {
			break
		}
		if !unicode.IsDigit(rune(line[0])) {
			continue
		}

		if strings.HasPrefix(line, vaddrHex) {
			fmt.Printf(indent+"\033[91m%s\033[0m\n", line[:len(line)-1])
		} else {
			fmt.Print(indent + line)
		}
	}
	return nil
}
