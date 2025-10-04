package coredump

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
)

type elfNote struct {
	Name string
	Type uint32
	Data []byte
}

func readNotesFromSegment(prog *elf.Prog) (out []elfNote, err error) {
	reader := io.NewSectionReader(prog, 0, int64(prog.Filesz))

	var nNamesz uint32
	var nDescsz uint32
	var nType uint32

	for {
		if err := binary.Read(reader, binary.LittleEndian, &nNamesz); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if err := binary.Read(reader, binary.LittleEndian, &nDescsz); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.LittleEndian, &nType); err != nil {
			return nil, err
		}

		name := make([]byte, nNamesz)
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, err
		}

		namePadding := (4 - (nNamesz % 4)) % 4
		if namePadding > 0 {
			reader.Seek(int64(namePadding), 1)
		}

		value := make([]byte, nDescsz)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}

		descPadding := (4 - (nDescsz % 4)) % 4
		if descPadding > 0 {
			reader.Seek(int64(descPadding), 1)
		}

		nameStr := string(name)
		if nullIndex := bytes.IndexByte(name, 0x00); nullIndex != -1 {
			nameStr = string(name[:nullIndex])
		}
		out = append(out, elfNote{Name: nameStr, Type: nType, Data: value})
	}
	return
}
