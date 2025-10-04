package vitacore

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

func u16(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset:])
}

func u32(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}

func c_str(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	nullByteIndex := bytes.IndexByte(data[offset:], 0x00)
	if nullByteIndex == -1 {
		return string(data[offset:])
	}
	return string(data[offset : offset+nullByteIndex])
}

func Hexdump(data []byte, prefix string) {
	const bytesPerRow = 16
	for i := 0; i < len(data); i += bytesPerRow {
		end := i + bytesPerRow
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]

		hexPart := bytes.Buffer{}
		for _, b := range row {
			hexPart.WriteString(fmt.Sprintf("%02x ", b))
		}
		for j := len(row); j < bytesPerRow; j++ {
			hexPart.WriteString("   ")
		}

		asciiPart := bytes.Buffer{}
		for _, b := range row {
			if b >= 32 && b <= 126 {
				asciiPart.WriteByte(b)
			} else {
				asciiPart.WriteByte('.')
			}
		}

		fmt.Printf("%s%08x: %s %s\n", prefix, i, hexPart.String(), asciiPart.String())
	}
}

type IndentedPrinter struct {
	level int
}

func NewIndentedPrinter() *IndentedPrinter {
	return &IndentedPrinter{}
}

func (ip *IndentedPrinter) Indent() {
	ip.level++
}

func (ip *IndentedPrinter) Dedent() {
	if ip.level > 0 {
		ip.level--
	}
}

func (ip *IndentedPrinter) Print(format string, a ...interface{}) {
	prefix := strings.Repeat("    ", ip.level)
	fmt.Printf("%s%s\n", prefix, fmt.Sprintf(format, a...))
}

func (ip *IndentedPrinter) PrinterFunc() func(format string, a ...interface{}) {
	return ip.Print
}
