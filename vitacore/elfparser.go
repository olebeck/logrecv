package vitacore

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	// Assuming Vita uses ARM EABI
)

// ElfParser parses the executable ELF file associated with the coredump.
type ElfParser struct {
	file     *elf.File
	closer   io.Closer
	filename string
	rxVaddr  uint64

	addr2lineCmd string
	objdumpCmd   string
}

// NewElfParser creates a new ElfParser instance.
func NewElfParser(filename string) (*ElfParser, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file %s: %w", filename, err)
	}

	elfFile, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to parse ELF file %s: %w", filename, err)
	}

	parser := &ElfParser{
		file:         elfFile,
		filename:     filename,
		addr2lineCmd: "arm-vita-eabi-addr2line",
		objdumpCmd:   "arm-vita-eabi-objdump",
	}

	if err := parser.parseSegments(); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to parse ELF segments: %w", err)
	}

	parser.closer = f
	return parser, nil
}

func (ep *ElfParser) Close() {
	if ep.closer != nil {
		ep.closer.Close()
	}
}

func (ep *ElfParser) parseSegments() error {
	for _, prog := range ep.file.Progs {
		// PT_LOAD segments hold the executable and data sections in memory.
		if prog.Type == elf.PT_LOAD {
			// p_flags 5 corresponds to RX (Read + Execute)
			if prog.Flags == elf.PF_R|elf.PF_X {
				ep.rxVaddr = prog.Vaddr
				// Assuming the first RX segment is the one we care about for disassembly offsets
				// In some cases, there might be multiple PT_LOAD segments.
				// The Python code explicitly looks for flags == 5.
				// The Go elf.ProgHeader Flags type is elf.Flags, which is a uint32.
				// We need to match the raw value 5 or check the flags bits.
				// elf.PF_R (4) | elf.PF_X (1) = 5
				// So checking `prog.Flags == elf.PF_R|elf.PF_X` is correct.
				return nil // Found the first RX segment, assume it's the one for offset calculation
			}
		}
	}
	return fmt.Errorf("no executable PT_LOAD segment (flags=RX) found")
}

func (ep *ElfParser) DisassembleAroundAddr(offset uint32) error {
	if ep.rxVaddr == 0 {
		return fmt.Errorf("executable segment virtual address not found")
	}

	addr := uint62uint32(ep.rxVaddr) + offset

	isThumb := (addr & 1) != 0
	if isThumb {
		addr &= ^uint32(1)
	}

	startAddr := addr - 0x30
	endAddr := addr + 0x30

	if startAddr > addr {
		startAddr = 0
	}
	if endAddr < addr {
		endAddr = 0xFFFFFFFF
	}

	args := []string{
		"-d", "-S",
		fmt.Sprintf("--start-address=0x%x", startAddr),
		fmt.Sprintf("--stop-address=0x%x", endAddr),
		ep.filename,
	}
	if isThumb {
		args = append(args, "-Mforce-thumb")
	}

	cmd := exec.Command(ep.objdumpCmd, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run %s: %w\nOutput:\n%s", ep.objdumpCmd, err, output)
	}

	lines := bytes.Split(output, []byte("\n"))
	var disasmLines []string
	inDisassemblySection := false

	for _, line := range lines {
		lineStr := string(line)
		if strings.Contains(lineStr, "Disassembly of section") {
			inDisassemblySection = true
			continue
		}
		if inDisassemblySection {
			if strings.Contains(lineStr, fmt.Sprintf("%x:", addr)) {
				parts := strings.SplitN(lineStr, "\t", 2)
				if len(parts) == 2 {
					lineStr = "!!! \t" + parts[1] + " !!!"
				}
				disasmLines = append(disasmLines, "\033[91m"+lineStr+"\033[0m") // Red
			} else {
				disasmLines = append(disasmLines, "\033[90m"+lineStr+"\033[0m") // Grey
			}
		}
	}

	fmt.Println(strings.Join(disasmLines, "\n"))

	return nil
}

func uint62uint32(u uint64) uint32 {
	if u > 0xFFFFFFFF {
		slog.Warn("uint64 address truncated to uint32", "address", u)
		return uint32(u)
	}
	return uint32(u)
}

func (ep *ElfParser) Addr2Line(offset uint32) (string, error) {
	if ep.rxVaddr == 0 {
		return "", fmt.Errorf("executable segment virtual address not found")
	}

	addr := uint62uint32(ep.rxVaddr) + offset

	args := []string{
		"-e", ep.filename,
		"-f", // Show function names
		"-p", // Pretty-print (path, file:line, function)
		"-C", // Demangle C++ names
		fmt.Sprintf("0x%x", addr),
	}

	cmd := exec.Command(ep.addr2lineCmd, args...)
	output, err := cmd.Output()
	if err != nil {
		outputStr := strings.TrimSpace(string(output))
		if strings.Contains(outputStr, "??:0") || strings.Contains(outputStr, "?? ??:0") {
			return outputStr, fmt.Errorf("no addr2line info found for address 0x%x: %w", addr, err)
		}
		return outputStr, fmt.Errorf("failed to run %s for 0x%x: %w\nOutput:\n%s", ep.addr2lineCmd, addr, err, output)
	}

	return strings.TrimSpace(string(output)), nil
}
