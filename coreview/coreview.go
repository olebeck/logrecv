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
	cd *coredump.Coredump

	elfFilename string
	elf         *elf.File

	syms []elf.Symbol
}

func NewCoreView(cd *coredump.Coredump, elfFilename string) (*CoreView, error) {
	cv := &CoreView{
		cd: cd,
	}

	if elfFilename != "" {
		var err error
		cv.elfFilename = elfFilename
		cv.elf, err = elf.Open(elfFilename)
		if err != nil {
			return nil, err
		}

		textSection := cv.elf.Section(".text")
		syms, err := cv.elf.Symbols()
		if err != nil {
			return nil, err
		}
		for _, sym := range syms {
			if sym.Value < textSection.Addr {
				continue
			}
			cv.syms = append(cv.syms, sym)
		}
		slices.SortFunc(cv.syms, func(a, b elf.Symbol) int {
			return int(a.Value) - int(b.Value)
		})
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
	if cv.elf != nil {
		err = cv.displayDisassembly(crashThreadID)
		if err != nil {
			logrus.Errorf("Error displaying disassembly: %s", err)
		}
	}
	cv.displayRegisters(crashThreadID)
	err = cv.displayStackContents(crashThreadID)
	if err != nil {
		logrus.Errorf("Error displaying stack contents: %s", err)
	}
	err = cv.displayStacktrace(crashThreadID)
	if err != nil {
		logrus.Errorf("Error displaying stack trace: %s", err)
	}
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

func (cv *CoreView) displayRegisters(threadID uint32) {
	fmt.Println("\n=== REGISTERS ===")
	registers := cv.cd.GetThreadRegisters(threadID)

	type regVal struct {
		Name  string
		Value uint32
	}
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

func (cv *CoreView) displayStackContents(threadID uint32) error {
	regs := cv.cd.GetThreadRegisters(threadID)
	fmt.Println("\n=== STACK CONTENTS ===")
	fmt.Printf("Stack Pointer: 0x%08x\n", regs.SP)

	var stackData = make([]byte, 256)
	_, err := cv.cd.ReadAt(stackData, int64(regs.SP))
	if err != nil {
		return err
	}

	for i := 0; i < len(stackData); i += 16 {
		end := min(i+16, len(stackData))

		fmt.Printf("0x%08x: ", regs.SP+uint32(i))

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
	return nil
}

func (cv *CoreView) displayStacktrace(threadID uint32) error {
	fmt.Println("\n=== STACK TRACE ===")
	regs := cv.cd.GetThreadRegisters(threadID)

	frames, err := UnwindStack(regs.PC, regs.SP, cv.cd)
	if err != nil {
		return err
	}

	for i, frame := range frames {
		fmt.Printf("Frame %d:\n", i)
		fmt.Printf("  PC: 0x%08x %s\n", frame.PC, cv.getFunctionName(frame.PC))
		fmt.Printf("  SP: 0x%08x\n", frame.SP)

		err := cv.showDisassembly(frame.PC, fmt.Sprintf("Frame %d", i), "  ")
		if err != nil {
			return err
		}
	}
	return nil
}

func (cv *CoreView) displayDisassembly(threadID uint32) error {
	regs := cv.cd.GetThreadRegisters(threadID)

	fmt.Println("\n=== PC DISASSEMBLY ===")
	fmt.Printf("PC: 0x%08x %s\n", regs.PC, cv.getFunctionName(regs.PC))
	if err := cv.showDisassembly(regs.PC, "PC", ""); err != nil {
		return err
	}
	fmt.Println()

	fmt.Println("\n=== LR DISASSEMBLY ===")
	fmt.Printf("LR: 0x%08x %s\n", regs.LR, cv.getFunctionName(regs.LR))
	if err := cv.showDisassembly(regs.LR, "LR", ""); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

func (cv *CoreView) findSymbol(vaddr uint32) string {
	_, segment := cv.cd.GetModuleInfoByVaddr(vaddr)
	relAddr := vaddr - segment.BaseAddr
	elfAddr := relAddr + 0x81000000
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
}

func (cv *CoreView) getAddressLocation(vaddr uint32) string {
	module, segment := cv.cd.GetModuleInfoByVaddr(vaddr)
	if module == nil {
		return "(unknown module)"
	}
	relAddr := vaddr - segment.BaseAddr
	return fmt.Sprintf("(%s)+0x%x", cstr(module.Name), relAddr)
}

func (cv *CoreView) getFunctionName(vaddr uint32) string {
	module, _ := cv.cd.GetModuleInfoByVaddr(vaddr)
	if module == nil {
		return "(unknown module)"
	}
	location := cv.getAddressLocation(vaddr)
	if module.Fingerprint == cv.cd.ProcessInfo.Fingerprint {
		sym := cv.findSymbol(vaddr)
		if sym != "" {
			return fmt.Sprintf("%s %s", location, sym)
		}
	}
	return location
}

func (cv *CoreView) disassembleAround(w io.Writer, vaddr uint32, colored bool) error {
	module, segment := cv.cd.GetModuleInfoByVaddr(vaddr)
	if module == nil {
		fmt.Fprintf(w, "no module at 0x%08x\n", vaddr)
	}
	if module.Fingerprint != cv.cd.ProcessInfo.Fingerprint {
		fmt.Fprintf(w, "not in main elf\n")
		return nil
	}

	relAddr := vaddr - segment.BaseAddr
	elfAddr := relAddr + 0x81000000
	startAddr := elfAddr - 16
	endAddr := startAddr + 32

	buf := bytes.NewBuffer(nil)
	cmd := exec.Command("arm-vita-eabi-objdump",
		"-d", "-S",
		"--start-address", fmt.Sprintf("0x%08x", startAddr),
		"--stop-address", fmt.Sprintf("0x%08x", endAddr),
		"--demangle",
		cv.elfFilename,
	)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	vaddrHex := fmt.Sprintf("%08x", elfAddr)
	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF {
			break
		}
		if !unicode.IsDigit(rune(line[0])) {
			continue
		}
		if strings.HasPrefix(line, vaddrHex) && colored {
			fmt.Printf("\033[91m%s\033[0m\n", line[:len(line)-1])
		} else {
			fmt.Print(line)
		}
	}
	return nil
}

func (cv *CoreView) showDisassembly(vaddr uint32, label, indent string) error {
	fmt.Printf(indent+"Disassembly around %s (0x%08x):\n", label, vaddr)
	return cv.disassembleAround(os.Stdout, vaddr, true)
}
