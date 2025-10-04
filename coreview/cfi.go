package coreview

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"logrecv/coredump"
)

type Registers = coredump.ThreadRegInfoInfo

type CIE struct {
	Length                uint32
	CIEId                 uint32
	Version               uint8
	Augmentation          string
	CodeAlignmentFactor   uint64
	DataAlignmentFactor   int64
	ReturnAddressRegister uint64
	InitialInstructions   []byte
	FDEPointerEncoding    uint8
	LSDAPointerEncoding   uint8
	PersonalityPointer    uint64
}

type FDE struct {
	Length       uint32
	CIEPointer   uint32
	PCBegin      uint32
	PCRange      uint32
	Instructions []byte
}

type CFIEntry struct {
	StartAddr    uint32
	EndAddr      uint32
	Instructions []byte
	CIE          *CIE // Reference to the Common Information Entry
}

func parseCFIEntries(data []byte) ([]CFIEntry, error) {
	var entries []CFIEntry
	var cies = make(map[uint32]*CIE) // Map CIE offset to CIE

	reader := bytes.NewReader(data)

	for {
		// Remember the current position for CIE offset calculations
		entryStart, _ := reader.Seek(0, io.SeekCurrent)

		// Read the length field (first 4 bytes)
		var length uint32
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read length: %v", err)
		}

		// Check for 64-bit DWARF format
		if length == 0xffffffff {
			// 64-bit DWARF format - read 8-byte length
			var length64 uint64
			if err := binary.Read(reader, binary.LittleEndian, &length64); err != nil {
				return nil, fmt.Errorf("failed to read 64-bit length: %v", err)
			}
			length = uint32(length64) // For simplicity, assume it fits in 32 bits
		}

		if length == 0 {
			break // End of entries
		}

		// Read the CIE ID / CIE pointer field
		var cieField uint32
		if err := binary.Read(reader, binary.LittleEndian, &cieField); err != nil {
			return nil, fmt.Errorf("failed to read CIE field: %v", err)
		}

		// Determine if this is a CIE or FDE
		if cieField == 0xffffffff { // This is a CIE
			cie, err := parseCIE(reader, length-4, uint32(entryStart))
			if err != nil {
				return nil, fmt.Errorf("failed to parse CIE: %v", err)
			}
			cies[uint32(entryStart)] = cie

		} else { // This is an FDE
			fde, err := parseFDE(reader, length-4, cieField, uint32(entryStart))
			if err != nil {
				return nil, fmt.Errorf("failed to parse FDE: %v", err)
			}

			// Find the corresponding CIE
			cie, exists := cies[cieField]
			if !exists {
				return nil, fmt.Errorf("CIE not found for FDE at offset %d", entryStart)
			}

			// Create CFI entry
			entry := CFIEntry{
				StartAddr:    fde.PCBegin,
				EndAddr:      fde.PCBegin + fde.PCRange,
				Instructions: fde.Instructions,
				CIE:          cie,
			}
			entries = append(entries, entry)
		}

		// Seek to the next entry
		nextPos := entryStart + int64(length) + 4
		if _, err := reader.Seek(nextPos, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to next entry: %v", err)
		}
	}

	return entries, nil
}

func parseCIE(reader *bytes.Reader, length uint32, offset uint32) (*CIE, error) {
	cie := &CIE{}
	cie.Length = length
	cie.CIEId = 0xffffffff

	// Read version
	if err := binary.Read(reader, binary.LittleEndian, &cie.Version); err != nil {
		return nil, fmt.Errorf("failed to read CIE version: %v", err)
	}

	// Read augmentation string (null-terminated)
	augBytes := make([]byte, 0)
	for {
		var b byte
		if err := binary.Read(reader, binary.LittleEndian, &b); err != nil {
			return nil, fmt.Errorf("failed to read augmentation byte: %v", err)
		}
		if b == 0 {
			break
		}
		augBytes = append(augBytes, b)
	}
	cie.Augmentation = string(augBytes)

	// Read code alignment factor (ULEB128)
	caf, err := readULEB128(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read code alignment factor: %v", err)
	}
	cie.CodeAlignmentFactor = caf

	// Read data alignment factor (SLEB128)
	daf, err := readSLEB128(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data alignment factor: %v", err)
	}
	cie.DataAlignmentFactor = daf

	// Read return address register
	if cie.Version == 1 {
		var reg uint8
		if err := binary.Read(reader, binary.LittleEndian, &reg); err != nil {
			return nil, fmt.Errorf("failed to read return address register: %v", err)
		}
		cie.ReturnAddressRegister = uint64(reg)
	} else {
		reg, err := readULEB128(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read return address register: %v", err)
		}
		cie.ReturnAddressRegister = reg
	}

	// Handle augmentation data
	var augmentationLength uint64
	if len(cie.Augmentation) > 0 && cie.Augmentation[0] == 'z' {
		augmentationLength, err = readULEB128(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read augmentation length: %v", err)
		}

		// Parse augmentation data
		augData := make([]byte, augmentationLength)
		if _, err := reader.Read(augData); err != nil {
			return nil, fmt.Errorf("failed to read augmentation data: %v", err)
		}

		// Parse specific augmentation flags
		for i := 1; i < len(cie.Augmentation); i++ {
			switch cie.Augmentation[i] {
			case 'L':
				cie.LSDAPointerEncoding = augData[0]
			case 'R':
				cie.FDEPointerEncoding = augData[0]
			case 'P':
				// Personality pointer - more complex parsing needed
			}
		}
	}

	// Calculate remaining bytes for initial instructions
	currentPos, _ := reader.Seek(0, io.SeekCurrent)
	startOffset := int64(offset) + 4 // Account for length field
	remainingBytes := int64(length) - (currentPos - startOffset)

	if remainingBytes > 0 {
		cie.InitialInstructions = make([]byte, remainingBytes)
		if _, err := reader.Read(cie.InitialInstructions); err != nil {
			return nil, fmt.Errorf("failed to read initial instructions: %v", err)
		}
	}

	return cie, nil
}

func parseFDE(reader *bytes.Reader, length uint32, ciePointer uint32, offset uint32) (*FDE, error) {
	fde := &FDE{}
	fde.Length = length
	fde.CIEPointer = ciePointer

	// Read PC begin
	if err := binary.Read(reader, binary.LittleEndian, &fde.PCBegin); err != nil {
		return nil, fmt.Errorf("failed to read PC begin: %v", err)
	}

	// Read PC range
	if err := binary.Read(reader, binary.LittleEndian, &fde.PCRange); err != nil {
		return nil, fmt.Errorf("failed to read PC range: %v", err)
	}

	// Handle augmentation data if present
	// This is simplified - real implementation would need to handle
	// the augmentation string from the corresponding CIE

	// Calculate remaining bytes for instructions
	currentPos, _ := reader.Seek(0, io.SeekCurrent)
	startOffset := int64(offset) + 4 // Account for length field
	remainingBytes := int64(length) - (currentPos - startOffset)

	if remainingBytes > 0 {
		fde.Instructions = make([]byte, remainingBytes)
		if _, err := reader.Read(fde.Instructions); err != nil {
			return nil, fmt.Errorf("failed to read FDE instructions: %v", err)
		}
	}

	return fde, nil
}

// ARM v7 register constants
const (
	RegR0  = 0
	RegR1  = 1
	RegR2  = 2
	RegR3  = 3
	RegR4  = 4
	RegR5  = 5
	RegR6  = 6
	RegR7  = 7 // Frame pointer in Thumb mode
	RegR8  = 8
	RegR9  = 9
	RegR10 = 10
	RegR11 = 11 // Frame pointer in ARM mode
	RegR12 = 12 // Intra-procedure call scratch register
	RegR13 = 13 // Stack pointer (SP)
	RegR14 = 14 // Link register (LR)
	RegR15 = 15 // Program counter (PC)

	// Aliases for clarity
	RegFP = RegR11 // Frame pointer (ARM mode)
	RegSP = RegR13 // Stack pointer
	RegLR = RegR14 // Link register
	RegPC = RegR15 // Program counter

	// VFP (Vector Floating Point) registers
	RegD0  = 64
	RegD1  = 65
	RegD2  = 66
	RegD3  = 67
	RegD4  = 68
	RegD5  = 69
	RegD6  = 70
	RegD7  = 71
	RegD8  = 72
	RegD9  = 73
	RegD10 = 74
	RegD11 = 75
	RegD12 = 76
	RegD13 = 77
	RegD14 = 78
	RegD15 = 79
)

func regIndexToReg(r *Registers, idx int) *uint32 {
	switch idx {
	case RegR0:
		return &r.R0
	case RegR1:
		return &r.R1
	case RegR2:
		return &r.R2
	case RegR3:
		return &r.R3
	case RegR4:
		return &r.R4
	case RegR5:
		return &r.R5
	case RegR6:
		return &r.R6
	case RegR7:
		return &r.R7
	case RegR8:
		return &r.R8
	case RegR9:
		return &r.R9
	case RegR10:
		return &r.R10
	case RegR11:
		return &r.R11
	case RegR12:
		return &r.R12
	case RegR13:
		return &r.SP
	case RegR14:
		return &r.LR
	case RegR15:
		return &r.PC
	}
	return nil
}

// CFI instruction opcodes (same as x86_64)
const (
	DW_CFA_advance_loc        = 0x40
	DW_CFA_offset             = 0x80
	DW_CFA_restore            = 0xc0
	DW_CFA_nop                = 0x00
	DW_CFA_set_loc            = 0x01
	DW_CFA_advance_loc1       = 0x02
	DW_CFA_advance_loc2       = 0x03
	DW_CFA_advance_loc4       = 0x04
	DW_CFA_offset_extended    = 0x05
	DW_CFA_restore_extended   = 0x06
	DW_CFA_undefined          = 0x07
	DW_CFA_same_value         = 0x08
	DW_CFA_register           = 0x09
	DW_CFA_remember_state     = 0x0a
	DW_CFA_restore_state      = 0x0b
	DW_CFA_def_cfa            = 0x0c
	DW_CFA_def_cfa_register   = 0x0d
	DW_CFA_def_cfa_offset     = 0x0e
	DW_CFA_def_cfa_expression = 0x0f
	DW_CFA_expression         = 0x10
	DW_CFA_offset_extended_sf = 0x11
	DW_CFA_def_cfa_sf         = 0x12
	DW_CFA_def_cfa_offset_sf  = 0x13
	DW_CFA_val_offset         = 0x14
	DW_CFA_val_offset_sf      = 0x15
	DW_CFA_val_expression     = 0x16
)

// ARM-specific calling convention constants
const (
	ARM_STACK_ALIGNMENT = 8 // ARM requires 8-byte stack alignment
	THUMB_BIT           = 1 // Bit 0 indicates Thumb mode
)

// RegisterRule represents how a register's value is determined
type RegisterRule struct {
	Type   int   // Rule type
	Offset int64 // Offset for offset-based rules
	Reg    int   // Register number for register-based rules
}

// Rule types
const (
	RuleUndefined = iota
	RuleSameValue
	RuleOffset
	RuleValOffset
	RuleRegister
	RuleExpression
	RuleValExpression
)

// UnwindContext holds the state for unwinding
type UnwindContext struct {
	CFARule       RegisterRule
	RegisterRules map[int]RegisterRule
	CodeFactor    uint64
	DataFactor    int64
	ReturnColumn  int
	StateStack    []map[int]RegisterRule // For remember/restore state
}

// StackFrame represents a single frame in the call stack
type StackFrame struct {
	PC        uint32 // ARM uses 32-bit addresses
	SP        uint32
	FP        uint32 // Frame pointer (R11 in ARM mode, R7 in Thumb)
	LR        uint32 // Link register
	IsThumb   bool   // Whether this frame is in Thumb mode
	Registers Registers
}

// MemoryReader interface for reading process memory
type MemoryReader interface {
	ReadUint32(addr uint32) (uint32, error)
	ReadBytes(addr uint32, size int) ([]byte, error)
}

// MockMemoryReader for testing
type MockMemoryReader struct {
	Memory map[uint32]uint32
}

func (m *MockMemoryReader) ReadUint32(addr uint32) (uint32, error) {
	if val, exists := m.Memory[addr]; exists {
		return val, nil
	}
	return 0, fmt.Errorf("address 0x%x not found in memory", addr)
}

func (m *MockMemoryReader) ReadBytes(addr uint32, size int) ([]byte, error) {
	result := make([]byte, size)
	for i := 0; i < size; i += 4 {
		val, err := m.ReadUint32(addr + uint32(i))
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(result[i:i+4], val)
	}
	return result, nil
}

// UnwindStack performs stack unwinding using CFI data for ARM v7
func UnwindStack(entries []CFIEntry, initialRegs *Registers, memory MemoryReader, maxFrames int) ([]StackFrame, error) {
	var frames []StackFrame
	var currentRegs Registers

	// Copy initial registers
	currentRegs = *initialRegs

	for len(frames) < maxFrames {
		currentPC := currentRegs.PC
		currentSP := currentRegs.SP
		currentFP := currentRegs.R11
		currentLR := currentRegs.LR

		// Determine if we're in Thumb mode
		isThumb := (currentPC & THUMB_BIT) != 0
		actualPC := currentPC &^ THUMB_BIT // Clear Thumb bit for address lookup

		// Create frame for current state
		frame := StackFrame{
			PC:        actualPC,
			SP:        currentSP,
			FP:        currentFP,
			LR:        currentLR,
			IsThumb:   isThumb,
			Registers: Registers{},
		}

		// Copy current registers to frame
		frame.Registers = currentRegs
		frames = append(frames, frame)

		if currentPC == 0 {
			break
		}

		// Find CFI entry for current PC
		cfiEntry := findCFIForAddress(entries, actualPC)
		if cfiEntry == nil {
			// No CFI found, try different unwinding strategies

			// Strategy 1: Use link register if available and valid
			if currentLR != 0 && currentLR != 0xffffffff {
				currentRegs.PC = currentLR
				// In leaf functions, LR might point to the return address
				// Clear LR to avoid infinite loops
				currentRegs.LR = 0
				continue
			}

			// Strategy 2: Frame pointer unwinding (if R11 is used as FP)
			if currentFP != 0 {
				// ARM frame layout: [prev_fp][saved_lr][local_vars...]
				// R11 points to prev_fp location
				prevFP, err := memory.ReadUint32(currentFP)
				if err != nil {
					break
				}

				savedLR, err := memory.ReadUint32(currentFP + 4)
				if err != nil {
					break
				}

				_ = prevFP
				currentRegs.PC = savedLR
				currentRegs.R11 = prevFP
				currentRegs.SP = currentFP + 8 // Skip saved FP and LR
				currentRegs.LR = 0
				continue
			}

			// Strategy 3: Simple stack scanning (last resort)
			// This is less reliable but sometimes works
			if currentSP != 0 {
				// Try to find a valid return address on the stack
				for offset := uint32(0); offset < 64; offset += 4 {
					addr := currentSP + offset
					val, err := memory.ReadUint32(addr)
					if err != nil {
						break
					}

					// Check if this looks like a valid code address
					if isValidCodeAddress(val) {
						currentRegs.PC = val
						currentRegs.SP = addr + 4
						currentRegs.LR = 0
						goto continueUnwind
					}
				}
			}

			break // No more unwinding possible

		continueUnwind:
			if currentRegs.PC == 0 {
				break
			}
			continue
		}

		// Execute CFI instructions to determine how to unwind
		context, err := executeCFIInstructions(cfiEntry, actualPC)
		if err != nil {
			return frames, fmt.Errorf("failed to execute CFI instructions: %v", err)
		}

		// Calculate CFA (Canonical Frame Address)
		cfa, err := calculateCFA(context.CFARule, currentRegs, memory)
		if err != nil {
			return frames, fmt.Errorf("failed to calculate CFA: %v", err)
		}

		// Restore registers based on CFI rules
		newRegs := Registers{}
		newRegs = currentRegs
		for reg, rule := range context.RegisterRules {
			val, err := restoreRegister(rule, cfa, currentRegs, memory)
			if err != nil {
				return frames, fmt.Errorf("failed to restore register %d: %v", reg, err)
			}
			if targetReg := regIndexToReg(&newRegs, reg); targetReg != nil {
				*targetReg = val
			}
		}

		// Restore return address (usually LR or PC)
		if returnRule, exists := context.RegisterRules[context.ReturnColumn]; exists {
			returnAddr, err := restoreRegister(returnRule, cfa, currentRegs, memory)
			if err != nil {
				return frames, fmt.Errorf("failed to restore return address: %v", err)
			}
			newRegs.PC = returnAddr
		} else if lrRule, exists := context.RegisterRules[RegLR]; exists {
			// If no explicit return column, use LR
			returnAddr, err := restoreRegister(lrRule, cfa, currentRegs, memory)
			if err != nil {
				return frames, fmt.Errorf("failed to restore LR: %v", err)
			}
			newRegs.PC = returnAddr
		}
		newRegs.LR = 0

		// Update SP to CFA
		newRegs.SP = cfa
		currentRegs = newRegs

		// Check if we've reached the end
		if currentRegs.PC == 0 {
			break
		}
	}

	return frames, nil
}

// isValidCodeAddress checks if an address looks like valid code
func isValidCodeAddress(addr uint32) bool {
	// ARM code addresses should be in reasonable ranges
	// This is a heuristic and should be adjusted based on your target
	if addr < 0x8000 || addr >= 0xffffffff {
		return false
	}

	// Check alignment - ARM instructions are 4-byte aligned, Thumb are 2-byte
	if addr&1 != 0 { // Thumb mode
		return (addr&1) == 1 && (addr&0xfffffffe) != 0
	} else { // ARM mode
		return (addr & 3) == 0
	}
}

// executeCFIInstructions processes CFI instructions for a specific PC
func executeCFIInstructions(entry *CFIEntry, pc uint32) (*UnwindContext, error) {
	context := &UnwindContext{
		RegisterRules: make(map[int]RegisterRule),
		CodeFactor:    entry.CIE.CodeAlignmentFactor,
		DataFactor:    entry.CIE.DataAlignmentFactor,
		ReturnColumn:  int(entry.CIE.ReturnAddressRegister),
		StateStack:    make([]map[int]RegisterRule, 0),
	}

	// ARM-specific defaults
	if context.CodeFactor == 0 {
		context.CodeFactor = 1 // ARM instructions are typically 1 byte aligned in CFI
	}
	if context.DataFactor == 0 {
		context.DataFactor = -4 // ARM stack grows downward, 4-byte words
	}
	if context.ReturnColumn == 0 {
		context.ReturnColumn = RegLR // ARM typically uses LR as return register
	}

	// Execute initial instructions from CIE
	if err := executeCFIInstructionBytes(entry.CIE.InitialInstructions, context, 0, entry.StartAddr); err != nil {
		return nil, fmt.Errorf("failed to execute CIE initial instructions: %v", err)
	}

	// Execute FDE instructions up to the current PC
	pcOffset := pc - entry.StartAddr
	if err := executeCFIInstructionBytes(entry.Instructions, context, pcOffset, entry.StartAddr); err != nil {
		return nil, fmt.Errorf("failed to execute FDE instructions: %v", err)
	}

	return context, nil
}

// executeCFIInstructionBytes processes a sequence of CFI instruction bytes
func executeCFIInstructionBytes(instructions []byte, context *UnwindContext, targetOffset uint32, baseAddr uint32) error {
	reader := bytes.NewReader(instructions)
	currentOffset := uint32(0)

	for reader.Len() > 0 {
		if currentOffset > targetOffset {
			break
		}

		var opcode byte
		if err := binary.Read(reader, binary.LittleEndian, &opcode); err != nil {
			return fmt.Errorf("failed to read opcode: %v", err)
		}

		switch {
		case opcode&0xc0 == DW_CFA_advance_loc:
			// DW_CFA_advance_loc
			delta := uint64(opcode & 0x3f)
			currentOffset += uint32(delta * context.CodeFactor)

		case opcode&0xc0 == DW_CFA_offset:
			// DW_CFA_offset
			reg := int(opcode & 0x3f)
			offset, err := readULEB128(reader)
			if err != nil {
				return fmt.Errorf("failed to read offset: %v", err)
			}
			context.RegisterRules[reg] = RegisterRule{
				Type:   RuleOffset,
				Offset: int64(offset) * context.DataFactor,
			}

		case opcode&0xc0 == DW_CFA_restore:
			// DW_CFA_restore
			reg := int(opcode & 0x3f)
			delete(context.RegisterRules, reg)

		case opcode == DW_CFA_nop:
			// No operation

		case opcode == DW_CFA_def_cfa:
			// DW_CFA_def_cfa
			reg, err := readULEB128(reader)
			if err != nil {
				return fmt.Errorf("failed to read CFA register: %v", err)
			}
			offset, err := readULEB128(reader)
			if err != nil {
				return fmt.Errorf("failed to read CFA offset: %v", err)
			}
			context.CFARule = RegisterRule{
				Type:   RuleOffset,
				Reg:    int(reg),
				Offset: int64(offset),
			}

		case opcode == DW_CFA_def_cfa_register:
			// DW_CFA_def_cfa_register
			reg, err := readULEB128(reader)
			if err != nil {
				return fmt.Errorf("failed to read CFA register: %v", err)
			}
			context.CFARule.Reg = int(reg)

		case opcode == DW_CFA_def_cfa_offset:
			// DW_CFA_def_cfa_offset
			offset, err := readULEB128(reader)
			if err != nil {
				return fmt.Errorf("failed to read CFA offset: %v", err)
			}
			context.CFARule.Offset = int64(offset)

		case opcode == DW_CFA_remember_state:
			// DW_CFA_remember_state
			state := make(map[int]RegisterRule)
			for reg, rule := range context.RegisterRules {
				state[reg] = rule
			}
			context.StateStack = append(context.StateStack, state)

		case opcode == DW_CFA_restore_state:
			// DW_CFA_restore_state
			if len(context.StateStack) > 0 {
				state := context.StateStack[len(context.StateStack)-1]
				context.StateStack = context.StateStack[:len(context.StateStack)-1]
				context.RegisterRules = state
			}

		case opcode == DW_CFA_advance_loc1:
			// DW_CFA_advance_loc1
			var delta uint8
			if err := binary.Read(reader, binary.LittleEndian, &delta); err != nil {
				return fmt.Errorf("failed to read advance_loc1: %v", err)
			}
			currentOffset += uint32(uint64(delta) * context.CodeFactor)

		case opcode == DW_CFA_advance_loc2:
			// DW_CFA_advance_loc2
			var delta uint16
			if err := binary.Read(reader, binary.LittleEndian, &delta); err != nil {
				return fmt.Errorf("failed to read advance_loc2: %v", err)
			}
			currentOffset += uint32(uint64(delta) * context.CodeFactor)

		case opcode == DW_CFA_advance_loc4:
			// DW_CFA_advance_loc4
			var delta uint32
			if err := binary.Read(reader, binary.LittleEndian, &delta); err != nil {
				return fmt.Errorf("failed to read advance_loc4: %v", err)
			}
			currentOffset += uint32(uint64(delta) * context.CodeFactor)

		default:
			// Skip unknown instructions
			fmt.Printf("Unknown CFI opcode: 0x%x\n", opcode)
		}
	}

	return nil
}

// calculateCFA computes the Canonical Frame Address
func calculateCFA(rule RegisterRule, regs Registers, memory MemoryReader) (uint32, error) {
	switch rule.Type {
	case RuleOffset:
		reg := regIndexToReg(&regs, rule.Reg)
		if reg == nil {
			return 0, fmt.Errorf("register %d not available for CFA calculation", rule.Reg)
		}
		return uint32(int64(*reg) + rule.Offset), nil
	default:
		return 0, fmt.Errorf("unsupported CFA rule type: %d", rule.Type)
	}
}

// restoreRegister restores a register value based on CFI rule
func restoreRegister(rule RegisterRule, cfa uint32, regs Registers, memory MemoryReader) (uint32, error) {
	switch rule.Type {
	case RuleOffset:
		// Value is stored at CFA + offset
		// HACK!!! should be +
		addr := uint32(int64(cfa) - rule.Offset)
		return memory.ReadUint32(addr)

	case RuleSameValue:
		// Register value is unchanged
		if reg := regIndexToReg(&regs, rule.Reg); reg != nil {
			return *reg, nil
		}
		return 0, fmt.Errorf("register %d not available", rule.Reg)

	case RuleRegister:
		// Value is in another register
		if reg := regIndexToReg(&regs, rule.Reg); reg != nil {
			return *reg, nil
		}
		return 0, fmt.Errorf("register %d not available", rule.Reg)

	case RuleUndefined:
		return 0, fmt.Errorf("register value is undefined")

	default:
		return 0, fmt.Errorf("unsupported register rule type: %d", rule.Type)
	}
}

// PrintStackTrace prints a formatted stack trace for ARM
func PrintStackTrace(frames []StackFrame) {
	fmt.Println("ARM v7 Stack Trace:")
	for i, frame := range frames {
		fmt.Printf("Frame %d:\n", i)
		fmt.Printf("  PC: 0x%08x", frame.PC)
		if frame.IsThumb {
			fmt.Printf(" (Thumb)")
		} else {
			fmt.Printf(" (ARM)")
		}
		fmt.Printf("\n")
		fmt.Printf("  SP: 0x%08x\n", frame.SP)
		fmt.Printf("  FP: 0x%08x\n", frame.FP)
		fmt.Printf("  LR: 0x%08x\n", frame.LR)

		// Print key ARM registers
		//for reg := RegR0; reg <= RegR12; reg++ {
		//	if val, exists := frame.Registers[reg]; exists {
		//		fmt.Printf("  R%d: 0x%08x\n", reg, val)
		//	}
		//}
		fmt.Println()
	}
}

// Helper functions for LEB128 reading (same as before)
func readULEB128(reader *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for {
		var b byte
		if err := binary.Read(reader, binary.LittleEndian, &b); err != nil {
			return 0, err
		}

		result |= uint64(b&0x7f) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
	}

	return result, nil
}

func readSLEB128(reader *bytes.Reader) (int64, error) {
	var result int64
	var shift uint
	var b byte

	for {
		if err := binary.Read(reader, binary.LittleEndian, &b); err != nil {
			return 0, err
		}

		result |= int64(b&0x7f) << shift
		shift += 7

		if (b & 0x80) == 0 {
			break
		}
	}

	// Sign extend if necessary
	if shift < 64 && (b&0x40) != 0 {
		result |= -(1 << shift)
	}

	return result, nil
}

// Placeholder for findCFIForAddress function
func findCFIForAddress(entries []CFIEntry, vaddr uint32) *CFIEntry {
	for i := range entries {
		if vaddr >= entries[i].StartAddr && vaddr < entries[i].EndAddr {
			return &entries[i]
		}
	}
	return nil
}
