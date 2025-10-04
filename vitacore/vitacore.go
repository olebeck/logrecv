package vitacore

import (
	"encoding/binary"
	"fmt"
)

func PrintCoredumpInfo(coredumpData []byte, titleID, elfFilename string) error {
	coreParser, err := NewCoreParser(coredumpData)
	if err != nil {
		return err
	}

	elfParser, err := NewElfParser(elfFilename)
	if err != nil {
		return err
	}

	printCoredumpInfo(coreParser, elfParser)
	return nil
}

func printCoredumpInfo(coreParser *CoreParser, elfParser *ElfParser) {
	printer := NewIndentedPrinter()
	iprint := printer.PrinterFunc()

	iprint("=== COREDUMP ANALYSIS ===")
	iprint("")

	iprint("=== THREADS ===")
	crashedThreads := []*VitaThread{}
	printer.Indent()
	for _, thread := range coreParser.Threads {
		printThreadInfo(printer, thread, elfParser, coreParser)
		if thread.StopReason != 0 {
			crashedThreads = append(crashedThreads, thread)
		}
	}
	printer.Dedent()
	iprint("")

	for _, thread := range crashedThreads {
		iprint("=== THREAD \"%s\" <0x%x> CRASHED (%s) ===",
			thread.Name, thread.UID, StopReasons[thread.StopReason])

		pc := coreParser.GetAddressNotation("PC", thread.PC)
		iprint(pc.String(elfParser))
		pc.PrintDisassemblyIfAvailable(elfParser, iprint)

		if thread.Regs != nil && thread.Regs.GPR[14] != thread.PC { // LR is GPR[14]
			lr := coreParser.GetAddressNotation("LR", thread.Regs.GPR[14])
			iprint(lr.String(elfParser))
			lr.PrintDisassemblyIfAvailable(elfParser, iprint)
		} else if thread.Regs == nil {
			iprint("LR: <registers not available>")
		}

		iprint("REGISTERS:")
		printer.Indent()
		if thread.Regs != nil {
			for i := 0; i < 16; i++ {
				regName := fmt.Sprintf("R%d", i)
				if name, ok := RegNames[i]; ok {
					regName = name
				}
				iprint("%s: 0x%x", regName, thread.Regs.GPR[i])
			}
		} else {
			iprint("<register data not available>")
		}
		printer.Dedent()
		iprint("")

		iprint("STACK CONTENTS AROUND SP:")
		printer.Indent()
		if thread.Regs != nil {
			sp := thread.Regs.GPR[13] // SP is GPR[13]
			stackSizeToPrint := 24

			// Read stack data from the core dump
			stackReadStart := sp - 16
			stackReadStart = stackReadStart & ^uint32(3)

			stackReadSize := 16 + uint32(stackSizeToPrint*4)

			stackData := coreParser.ReadVaddr(stackReadStart, int(stackReadSize))

			if len(stackData) > 0 {
				for i := 0; i < int(stackReadSize)/4; i++ {
					addr := stackReadStart + uint32(i*4)
					if int(i*4+4) > len(stackData) {
						break
					}
					data := binary.LittleEndian.Uint32(stackData[i*4:])

					prefix := "    "
					if addr == sp {
						prefix = "SP =>"
					}
					dataNotation := coreParser.GetAddressNotation(fmt.Sprintf("%s 0x%x", prefix, addr), data)
					iprint(dataNotation.String(elfParser))
				}
				if uint32(len(stackData)) < stackReadSize {
					iprint("... [truncated stack data]")
				}
			} else {
				iprint("<stack data not available or SP is invalid>")
			}
		} else {
			iprint("<stack data not available (registers missing)>")
		}
		printer.Dedent()
		iprint("")
	}
}

func printThreadInfo(printer *IndentedPrinter, thread *VitaThread, elf *ElfParser, core *CoreParser) {
	iprint := printer.PrinterFunc()
	iprint(thread.Name)
	printer.Indent()
	iprint("ID: 0x%x", thread.UID)
	stopReasonStr := StopReasons[thread.StopReason]
	if stopReasonStr == "" && thread.StopReason != 0 {
		stopReasonStr = fmt.Sprintf("Unknown (0x%x)", thread.StopReason)
	}
	iprint("Stop reason: %s", stopReasonStr)

	statusStr := ThreadStatus[thread.Status]
	if statusStr == "" {
		statusStr = fmt.Sprintf("Unknown (0x%x)", thread.Status)
	}
	iprint("Status: %s", statusStr)

	pc := core.GetAddressNotation("PC", thread.PC)
	iprint(pc.String(elf))
	if thread.Regs != nil && thread.Regs.GPR[14] != thread.PC {
		lr := core.GetAddressNotation("LR", thread.Regs.GPR[14])
		iprint(lr.String(elf))
	} else if thread.Regs == nil {
		iprint("LR: <registers not available>")
	}
	printer.Dedent()
}

func printModuleInfo(printer *IndentedPrinter, module *VitaModule) {
	iprint := printer.PrinterFunc()
	iprint(module.Name)
	printer.Indent()
	for i, segment := range module.Segments {
		iprint("Segment %d", i+1)
		printer.Indent()
		iprint("Start: 0x%x", segment.Start)
		iprint("Size: 0x%x bytes", segment.Size)
		attrStr := SegmentAttributes[segment.Attr&0xF]
		if attrStr == "" {
			attrStr = fmt.Sprintf("Unknown (0x%x)", segment.Attr&0xF)
		}
		iprint("Attributes: 0x%x (%s)", segment.Attr, attrStr)
		iprint("Alignment: 0x%x", segment.Align)
		printer.Dedent()
	}
	printer.Dedent()
}
