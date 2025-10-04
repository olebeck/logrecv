package vitacore

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"maps"
)

type CoreParser struct {
	file     *elf.File
	notes    map[string][]byte
	Segments []*Segment
	Modules  []*VitaModule
	Threads  []*VitaThread
}

func NewCoreParser(data []byte) (*CoreParser, error) {
	br := bytes.NewReader(data)
	gz, err := gzip.NewReader(br)
	if err == nil {
		data, err := io.ReadAll(gz)
		if err != nil {
			return nil, err
		}
		br = bytes.NewReader(data)
	}

	coreElf, err := elf.NewFile(br)
	if err != nil {
		return nil, fmt.Errorf("failed to parse core ELF file: %w", err)
	}

	parser := &CoreParser{
		file:  coreElf,
		notes: make(map[string][]byte),
	}

	if err := parser.initNotesAndSegments(); err != nil {
		return nil, fmt.Errorf("failed to parse core notes and segments: %w", err)
	}

	if err := parser.parseModules(); err != nil {
		return nil, fmt.Errorf("failed to parse core modules: %w", err)
	}

	if err := parser.parseThreads(); err != nil {
		return nil, fmt.Errorf("failed to parse core threads: %w", err)
	}

	if err := parser.parseThreadRegs(); err != nil {
		return nil, fmt.Errorf("failed to parse core thread registers: %w", err)
	}

	return parser, nil
}

func readNotesFromSegment(data []byte) (map[string][]byte, error) {
	notesMap := make(map[string][]byte)
	reader := bytes.NewReader(data)

	var nNamesz uint32
	var nDescsz uint32
	var nType uint32

	for reader.Len() > 0 {
		if err := binary.Read(reader, binary.LittleEndian, &nNamesz); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read n_namesz: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &nDescsz); err != nil {
			return nil, fmt.Errorf("failed to read n_descsz: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &nType); err != nil {
			return nil, fmt.Errorf("failed to read n_type: %w", err)
		}

		name := make([]byte, nNamesz)
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, fmt.Errorf("failed to read note name (%d bytes): %w", nNamesz, err)
		}

		namePadding := (4 - (nNamesz % 4)) % 4
		if namePadding > 0 {
			reader.Seek(int64(namePadding), 1)
		}

		description := make([]byte, nDescsz)
		if _, err := io.ReadFull(reader, description); err != nil {
			return nil, fmt.Errorf("failed to read note description (%d bytes): %w", nDescsz, err)
		}

		descPadding := (4 - (nDescsz % 4)) % 4
		if descPadding > 0 {
			reader.Seek(int64(descPadding), 1)
		}

		nameStr := string(name)
		if nullIndex := bytes.IndexByte(name, 0x00); nullIndex != -1 {
			nameStr = string(name[:nullIndex])
		}

		notesMap[nameStr] = description
	}

	if reader.Len() != 0 {
		slog.Warn("Finished parsing notes but reader has remaining data", "remaining_bytes", reader.Len())
	}

	return notesMap, nil
}

func (cp *CoreParser) initNotesAndSegments() error {
	cp.notes = make(map[string][]byte)
	for _, prog := range cp.file.Progs {
		switch prog.Type {
		case elf.PT_NOTE:
			sectionData, err := io.ReadAll(prog.Open())
			if err != nil {
				return fmt.Errorf("failed to read PT_NOTE segment data: %w", err)
			}
			notes, err := readNotesFromSegment(sectionData)
			if err != nil {
				return err
			}
			maps.Copy(cp.notes, notes)

		case elf.PT_LOAD:
			segmentData, err := io.ReadAll(prog.Open())
			if err != nil {
				return fmt.Errorf("failed to read PT_LOAD segment data: %w", err)
			}
			cp.Segments = append(cp.Segments, &Segment{
				Vaddr: uint32(prog.Vaddr),
				Data:  segmentData,
				Size:  uint32(prog.Filesz),
			})
		}
	}
	if len(cp.notes) == 0 {
		return fmt.Errorf("no PT_NOTE segments found in core dump")
	}
	return nil
}

func (cp *CoreParser) parseModules() error {
	data, ok := cp.notes["MODULE_INFO"]
	if !ok {
		return fmt.Errorf("MODULE_INFO note not found")
	}

	if len(data) < 8 {
		return fmt.Errorf("MODULE_INFO note data is too short")
	}

	totalSize := u32(data, 0)
	numModules := u32(data, 4)
	offset := uint32(8)
	_ = totalSize

	for i := uint32(0); i < numModules; i++ {
		headSize := uint32(0x50)
		if offset+headSize > uint32(len(data)) {
			return fmt.Errorf("MODULE_INFO data truncated while parsing module head %d", i)
		}
		module := &VitaModule{
			UID:     u32(data, int(offset)+4),
			NumSegs: u32(data, int(offset)+0x4C),
			Name:    c_str(data, int(offset)+0x24),
		}
		offset += headSize

		segSizePer := uint32(0x14)
		totalSegSize := module.NumSegs * segSizePer
		if offset+totalSegSize > uint32(len(data)) {
			return fmt.Errorf("MODULE_INFO data truncated while parsing module segments for module %s", module.Name)
		}
		module.Segments = make([]*VitaModuleSegment, module.NumSegs)
		for j := uint32(0); j < module.NumSegs; j++ {
			segData := data[offset+j*segSizePer : offset+(j+1)*segSizePer]
			module.Segments[j] = &VitaModuleSegment{
				Num:   int(j + 1),
				Attr:  u32(segData, 4),
				Start: u32(segData, 8),
				Size:  u32(segData, 12),
				Align: u32(segData, 16),
			}
		}
		offset += totalSegSize

		footSize := uint32(0x10)
		if offset+footSize > uint32(len(data)) {
			return fmt.Errorf("MODULE_INFO data truncated while parsing module foot for module %s", module.Name)
		}
		vitaModuleFoot := data[offset : offset+footSize]
		_ = vitaModuleFoot
		offset += footSize

		cp.Modules = append(cp.Modules, module)
	}

	if offset != uint32(len(data)) {
		slog.Warn("MODULE_INFO data size mismatch after parsing", "parsed_size", offset, "actual_size", len(data))
	}

	return nil
}

func (cp *CoreParser) parseThreads() error {
	data, ok := cp.notes["THREAD_INFO"]
	if !ok {
		return fmt.Errorf("THREAD_INFO note not found")
	}

	if len(data) < 8 {
		return fmt.Errorf("THREAD_INFO note data is too short")
	}

	numThreads := u32(data, 4)
	offset := uint32(8)

	for i := uint32(0); i < numThreads; i++ {
		if offset+4 > uint32(len(data)) {
			return fmt.Errorf("THREAD_INFO data truncated while reading thread size %d", i)
		}
		threadSize := u32(data, int(offset))

		if offset+threadSize > uint32(len(data)) {
			return fmt.Errorf("THREAD_INFO data truncated while parsing thread data %d (size %d)", i, threadSize)
		}
		threadData := data[offset : offset+threadSize]

		thread := &VitaThread{
			UID:        u32(threadData, 4),
			Name:       c_str(threadData, 8),
			StopReason: u32(threadData, 0x74),
			Status:     u16(threadData, 0x30),
			PC:         u32(threadData, 0x9C),
		}
		cp.Threads = append(cp.Threads, thread)
		offset += threadSize
	}

	if offset != uint32(len(data)) {
		slog.Warn("THREAD_INFO data size mismatch after parsing", "parsed_size", offset, "actual_size", len(data))
	}

	return nil
}

func (cp *CoreParser) parseThreadRegs() error {
	data, ok := cp.notes["THREAD_REG_INFO"]
	if !ok {
		slog.Warn("THREAD_REG_INFO note not found, cannot parse registers")
		for _, thread := range cp.Threads {
			thread.Regs = nil
		}
		return nil
	}

	if len(data) < 8 {
		return fmt.Errorf("THREAD_REG_INFO note data is too short")
	}

	totalSize := u32(data, 0)
	numRegSets := u32(data, 4)
	offset := uint32(8)
	_ = totalSize

	for i := uint32(0); i < numRegSets; i++ {
		if offset+4 > uint32(len(data)) {
			return fmt.Errorf("THREAD_REG_INFO data truncated while reading reg set size %d", i)
		}
		regSetSize := u32(data, int(offset))

		if offset+regSetSize > uint32(len(data)) {
			return fmt.Errorf("THREAD_REG_INFO data truncated while parsing reg set data %d (size %d)", i, regSetSize)
		}
		regSetData := data[offset : offset+regSetSize]

		regs := &VitaRegs{
			TID: u32(regSetData, 4),
		}
		if len(regSetData) >= 8+16*4 {
			for j := 0; j < 16; j++ {
				regs.GPR[j] = u32(regSetData, 8+j*4)
			}
		} else {
			slog.Warn("THREAD_REG_INFO reg set data too short for 16 GPRs", "index", i, "data_size", len(regSetData))
		}

		var found bool
		for _, thr := range cp.Threads {
			if thr.UID == regs.TID {
				thr.Regs = regs
				found = true
				break
			}
		}
		if !found {
			slog.Warn("THREAD_REG_INFO reg set found for unknown thread ID", "tid", regs.TID)
		}

		offset += regSetSize
	}

	if offset != uint32(len(data)) {
		slog.Warn("THREAD_REG_INFO data size mismatch after parsing", "parsed_size", offset, "actual_size", len(data))
	}

	return nil
}

func (cp *CoreParser) GetAddressNotation(symbol string, vaddr uint32) *VitaAddress {
	for _, module := range cp.Modules {
		for _, segment := range module.Segments {
			if vaddr >= segment.Start && vaddr < segment.Start+segment.Size {
				return &VitaAddress{
					Symbol:  symbol,
					Vaddr:   vaddr,
					Module:  module,
					Segment: segment,
					Offset:  vaddr - segment.Start,
				}
			}
		}
	}
	return &VitaAddress{
		Symbol: symbol,
		Vaddr:  vaddr,
	}
}

// ReadVaddr reads data from the core dump's loaded segments at a specific virtual address.
func (cp *CoreParser) ReadVaddr(addr uint32, size int) []byte {
	for _, segment := range cp.Segments {
		// Check if the requested address range is within this segment
		if addr >= segment.Vaddr && addr < segment.Vaddr+segment.Size {
			// Calculate the offset within the segment's data
			offsetInSegment := int(addr - segment.Vaddr)
			// Ensure the requested size does not go beyond the segment's data
			if offsetInSegment+size <= len(segment.Data) {
				return segment.Data[offsetInSegment : offsetInSegment+size]
			}
			endIndex := min(offsetInSegment+size, len(segment.Data))
			return segment.Data[offsetInSegment:endIndex]
		}
	}
	return nil
}
