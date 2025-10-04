package coredump

import (
	"fmt"

	"github.com/ghostiam/binstruct"
)

func AlignedString(r binstruct.Reader) (string, error) {
	length, err := r.ReadUint32()
	if err != nil {
		return "", err
	}
	alignedSize := (length + 3) &^ 3
	_, data, err := r.ReadBytes(int(alignedSize))
	if err != nil {
		return "", err
	}
	if len(data) < int(alignedSize) {
		return "", fmt.Errorf("insufficient data for aligned string")
	}
	return string(data[:length]), nil
}
