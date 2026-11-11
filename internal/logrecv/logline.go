package logrecv

import (
	"fmt"
	"net/netip"
)

// LogLine is a single log line received from a device.
type LogLine struct {
	Source netip.Addr
	Text   string
}

// FormatLogline renders a log line the same way the server prints it locally.
func FormatLogline(ll LogLine) string {
	id := ll.Source.As4()[3]
	return fmt.Sprintf("\x1b[38;5;%dm% 3d\x1b[0m: %s\n", id, id, ll.Text)
}
