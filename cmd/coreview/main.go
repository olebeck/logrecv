package main

import (
	"flag"
	"log/slog"
	"logrecv/coredump"
	"logrecv/coreview"
	"os"
)

func readCoredump(filename string) (*coredump.Coredump, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return coredump.ParseCoredump(data)
}

func main() {
	flag.Parse()

	coredumpFilename := flag.Arg(0)
	elfFilename := flag.Arg(1)

	if coredumpFilename == "" {
		slog.Error("missing coredumpFilename")
		os.Exit(1)
	}

	cd, err := readCoredump(coredumpFilename)
	if err != nil {
		slog.Error("readCoredump", "error", err)
		os.Exit(1)
	}

	cv, err := coreview.NewCoreView(cd, elfFilename)
	if err != nil {
		slog.Error("NewCoreView", "error", err)
		os.Exit(1)
	}
	defer cv.Close()
	cv.Display()
}
