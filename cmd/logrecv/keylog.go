package main

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	keylogTxt *os.File
	keylogMu  sync.Mutex

	clientRandomRegex = regexp.MustCompile(`CLIENT_RANDOM [a-f\d]{64} [a-f\d]{96}`)
)

func openKeylog(filename string) error {
	var err error
	keylogTxt, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open keylog file: %w", err)
	}
	logrus.Info("Keylog file opened successfully")
	return nil
}

func writeKeylog(line string) {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if keylogTxt != nil {
		if _, err := keylogTxt.WriteString(line + "\n"); err != nil {
			logrus.WithError(err).Error("failed to write to keylog file")
		}
	}
}
