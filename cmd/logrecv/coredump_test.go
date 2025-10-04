package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestDownload(t *testing.T) {
	handleLogLineCoredump(netip.MustParseAddr("192.168.178.55"), "3:0x9cd098e26c7c132a:0x8c2ff5fd:[coredump] start ID=LEGO00001")
	handleLogLineCoredump(netip.MustParseAddr("192.168.178.55"), "3:0x9cd098e2e133745a:0x8c2ff5fd:[coredump] done")
	time.Sleep(1000 * time.Second)
}
