package coreview

import (
	"encoding/binary"
	"fmt"
	"io"
	"logrecv/coredump"
)

type Frame struct {
	PC uint32
	SP uint32
}

func UnwindStack(pc, sp uint32, cd *coredump.Coredump) ([]Frame, error) {
	var frames []Frame

	frames = append(frames, Frame{
		PC: pc,
		SP: sp,
	})

	for {
		lastFrame := frames[len(frames)-1]
		module, _ := cd.GetModuleInfoByVaddr(lastFrame.PC)
		if module == nil {
			return nil, fmt.Errorf("module not found")
		}

		if module.ArmExidxStart == module.ArmExidxEnd {
			return frames, nil
		}

		entry, err := findExidx(lastFrame.PC, module.ArmExidxStart, module.ArmExidxEnd, cd)
		if err != nil {
			return nil, err
		}

		newPC, newSP, err := applyExtabUnwind(lastFrame.PC, lastFrame.SP, entry.descriptor, cd)
		if err != nil {
			return nil, err
		}

		frames = append(frames, Frame{
			PC: newPC,
			SP: newSP,
		})
	}
}

type exidxEntry struct {
	pc         uint32
	descriptor uint32
}

func findExidx(pc uint32, exidxStart, exidxEnd uint32, memory io.ReaderAt) (exidxEntry, error) {
	const entrySize = 8
	exidxSize := exidxEnd - exidxStart
	if exidxSize == 0 || exidxSize%entrySize != 0 {
		return exidxEntry{}, fmt.Errorf("invalid .ARM.exidx size: %d bytes", exidxSize)
	}
	numEntries := int(exidxSize / entrySize)

	low := 0
	high := numEntries - 1
	foundIndex := -1
	startPC := uint32(0)
	startDescriptor := uint32(0)

	for low <= high {
		mid := low + (high-low)/2
		offset := int64(mid * entrySize)
		entryAddr := exidxStart + uint32(offset)

		var buf [8]byte
		n, err := memory.ReadAt(buf[:], int64(exidxStart)+offset)
		if err != nil || n != 8 {
			return exidxEntry{}, fmt.Errorf("failed to read exidx PC offset at index %d: %w", mid, err)
		}
		entryValue := binary.LittleEndian.Uint32(buf[:4])
		descriptor := binary.LittleEndian.Uint32(buf[4:])

		offset31 := int32(entryValue<<1) >> 1
		entryPC := uint32(int32(entryAddr) + offset31)

		if entryPC <= pc {
			foundIndex = mid
			startPC = entryPC
			startDescriptor = descriptor
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if foundIndex == -1 {
		return exidxEntry{}, fmt.Errorf("PC 0x%X not found in .ARM.exidx range [0x%X, 0x%X]", pc, exidxStart, exidxEnd)
	}

	return exidxEntry{
		descriptor: startDescriptor,
		pc:         startPC,
	}, nil
}

func applyExtabUnwind(
	oldPC, oldSP uint32,
	descriptor uint32,
	memory io.ReaderAt,
) (newPC, newSP uint32, err error) {
	compact := (descriptor & 0x80000000) != 0
	if compact {
		return applyCompactUnwind(oldPC, oldSP, descriptor)
	}

	offset := int32(descriptor<<1) >> 1
	extabAddr := int64(oldPC) + int64(offset)

	var extabEntry uint32
	buf := make([]byte, 4)
	if _, err := memory.ReadAt(buf, extabAddr); err != nil {
		return 0, 0, fmt.Errorf("failed to read extab entry: %w", err)
	}
	extabEntry = binary.LittleEndian.Uint32(buf)

	if extabEntry&0x80000000 != 0 {
		return applyCompactUnwind(oldPC, oldSP, extabEntry)
	}
	return applyGenericUnwind(oldPC, oldSP, extabAddr+4, memory)
}

func applyCompactUnwind(oldPC, oldSP uint32, descriptor uint32) (newPC, newSP uint32, err error) {
	personality := (descriptor >> 24) & 0x0F

	vsp := oldSP

	opcodes := []byte{
		byte((descriptor >> 16) & 0xFF),
		byte((descriptor >> 8) & 0xFF),
		byte(descriptor & 0xFF),
	}

	switch personality {
	case 0: // SU16
		// Format: 0x80 | offset
		// vsp = vsp + ((offset << 2) + 4)
		offset := descriptor & 0x00FFFFFF
		if opcodes[0] == 0 && opcodes[1] == 0 && opcodes[2] == 0 {
			// EXIDX_CANTUNWIND
			return 0, 0, fmt.Errorf("cannot unwind")
		}
		return executeUnwindOpcodes(opcodes, vsp+offset)

	case 1, 2: // LU16/LU32
		return executeUnwindOpcodes(opcodes, vsp)

	default:
		return 0, 0, fmt.Errorf("unsupported personality routine: 0x%X", personality)
	}
}

func applyGenericUnwind(oldPC, oldSP uint32, dataAddr int64, memory io.ReaderAt) (newPC, newSP uint32, err error) {
	buf := make([]byte, 64)
	if _, err := memory.ReadAt(buf, dataAddr); err != nil {
		return 0, 0, fmt.Errorf("failed to read unwind opcodes: %w", err)
	}
	return executeUnwindOpcodes(buf, oldSP)
}

func executeUnwindOpcodes(opcodes []byte, vsp uint32) (pc, sp uint32, err error) {
	// Virtual register file (r0-r15)
	regs := make(map[int]uint32)
	regs[13] = vsp // SP

	i := 0
	for i < len(opcodes) {
		op := opcodes[i]

		if op == 0xB0 {
			// Finish
			break
		}

		if op == 0x00 {
			// Padding/end
			i++
			continue
		}

		switch {
		case op >= 0x00 && op <= 0x3F:
			// vsp = vsp + (xxxxxx << 2) + 4
			vsp += (uint32(op&0x3F) << 2) + 4

		case op >= 0x40 && op <= 0x7F:
			// vsp = vsp - (xxxxxx << 2) - 4
			vsp -= (uint32(op&0x3F) << 2) + 4

		case op >= 0x80 && op <= 0x8F:
			// Pop registers under mask {r4-r15}
			if i+1 >= len(opcodes) {
				return 0, 0, fmt.Errorf("incomplete pop opcode")
			}
			i++
			mask := (uint32(op&0x0F) << 8) | uint32(opcodes[i])
			vsp, err = popRegisters(mask, 4, vsp, regs)
			if err != nil {
				return 0, 0, err
			}

		case op >= 0x90 && op <= 0x9F:
			// Set vsp = r[nnnn]
			reg := int(op & 0x0F)
			if val, ok := regs[reg]; ok {
				vsp = val
			} else {
				return 0, 0, fmt.Errorf("register r%d not available", reg)
			}

		case op >= 0xA0 && op <= 0xA7:
			// Pop r4-r[4+nnn]
			count := int(op&0x07) + 1
			mask := uint32((1<<count)-1) << 4
			vsp, err = popRegisters(mask, 4, vsp, regs)
			if err != nil {
				return 0, 0, err
			}

		case op >= 0xA8 && op <= 0xAF:
			// Pop r4-r[4+nnn], r14
			count := int(op&0x07) + 1
			mask := (uint32((1<<count)-1) << 4) | (1 << 14)
			vsp, err = popRegisters(mask, 4, vsp, regs)
			if err != nil {
				return 0, 0, err
			}

		case op == 0xB1:
			// Pop register mask (next byte)
			if i+1 >= len(opcodes) {
				return 0, 0, fmt.Errorf("incomplete pop mask opcode")
			}
			i++
			mask := uint32(opcodes[i])
			if mask == 0 {
				// Finish
				break
			}
			vsp, err = popRegisters(mask, 0, vsp, regs)
			if err != nil {
				return 0, 0, err
			}

		case op == 0xB2:
			// vsp = vsp + 0x204 + (uleb128 << 2)
			i++
			uleb, size := decodeULEB128(opcodes[i:])
			i += size - 1
			vsp += 0x204 + (uleb << 2)

		case op == 0xB3:
			// Pop VFP double-precision registers
			i++
			if i >= len(opcodes) {
				return 0, 0, fmt.Errorf("incomplete VFP pop")
			}
			// Skip VFP registers for now
			count := int(opcodes[i]&0x0F) + 1
			vsp += uint32(count * 8)

		default:
			return 0, 0, fmt.Errorf("unsupported unwind opcode: 0x%02X", op)
		}

		i++
	}

	// Get PC from r14 (LR) or popped r15
	pc = 0
	if val, ok := regs[15]; ok {
		pc = val
	} else if val, ok := regs[14]; ok {
		pc = val
	}

	regs[13] = vsp
	sp = vsp

	return pc, sp, nil
}

func popRegisters(mask uint32, startReg int, vsp uint32, regs map[int]uint32) (uint32, error) {
	for i := range 16 {
		if mask&(1<<uint(i)) != 0 {
			// In real implementation, read from memory
			// For now, simulate with placeholder values
			regs[startReg+i] = vsp
			vsp += 4
		}
	}
	return vsp, nil
}

func decodeULEB128(data []byte) (value uint32, size int) {
	var shift uint
	for i, b := range data {
		value |= uint32(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			return value, i + 1
		}
	}
	return value, len(data)
}
