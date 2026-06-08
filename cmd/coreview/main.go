package main

import (
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
	args := os.Args[1:]
	if len(args) != 2 {
		slog.Error("wrong number of arguments")
		return
	}
	elfFilename := args[0]
	coredumpFilename := args[1]

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
