package main

import (
	"encoding/json"
	"logrecv/coredump"
	"logrecv/coreview"
	"os"

	"github.com/sirupsen/logrus"
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
		logrus.Error("wrong number of arguments")
		return
	}
	elfFilename := args[0]
	coredumpFilename := args[1]

	cd, err := readCoredump(coredumpFilename)
	if err != nil {
		logrus.Fatal(err)
	}

	f, err := os.Create("test.json")
	if err != nil {
		logrus.Fatal(err)
	}
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	e.Encode(cd)

	cv, err := coreview.NewCoreView(cd, elfFilename)
	if err != nil {
		logrus.Fatal(err)
	}
	defer cv.Close()
	cv.Display()
}
