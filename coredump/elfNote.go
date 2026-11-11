package coredump

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Note struct {
	Name string
	Type uint32
	Data []byte
}

func readNotesFromSegment(r io.Reader) ([]Note, error) {
	type NoteHeader struct {
		NameSize uint32
		DescSize uint32
		Type     uint32
	}
	var notes []Note
	for {
		var head NoteHeader
		err := binary.Read(r, binary.LittleEndian, &head)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		var name = make([]byte, head.NameSize)
		_, err = io.ReadFull(r, name)
		if err != nil {
			return nil, err
		}
		io.CopyN(io.Discard, r, int64(4-(head.NameSize%4))%4)

		var desc = make([]byte, head.DescSize)
		n, err := io.ReadFull(r, desc)
		if err != nil {
			return nil, err
		}
		_ = n
		io.CopyN(io.Discard, r, int64(4-head.DescSize%4)%4)

		name, _, _ = bytes.Cut(name, []byte{0})
		notes = append(notes, Note{
			Name: string(name),
			Type: head.Type,
			Data: desc,
		})
	}
	return notes, nil
}
