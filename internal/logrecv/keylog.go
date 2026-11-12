package logrecv

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"sync"
)

var clientRandomRegex = regexp.MustCompile(`CLIENT_RANDOM [a-f\d]{64} [a-f\d]{96}`)

type keylogWriter struct {
	mu   sync.Mutex
	file *os.File
	hub  *Hub[string]
	last []string
}

func newKeylogWriter(filename string, hub *Hub[string]) (*keylogWriter, error) {
	k := &keylogWriter{hub: hub}
	if filename == "" {
		return k, nil
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	k.file = f
	return k, nil
}

func (k *keylogWriter) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.file == nil {
		return nil
	}
	err := k.file.Close()
	k.file = nil
	return err
}

func (k *keylogWriter) Handle(ll LogLine) bool {
	if !clientRandomRegex.MatchString(ll.Text) {
		return false
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if slices.Contains(k.last, ll.Text) {
		return true
	}
	k.last = append(k.last, ll.Text)
	if len(k.last) > 10 {
		k.last = k.last[1:]
	}

	if k.file != nil {
		if _, err := fmt.Fprintln(k.file, ll.Text); err != nil {
			slog.Error("failed to write to keylog file", "error", err)
		} else if err := k.file.Sync(); err != nil {
			slog.Error("failed to sync keylog file", "error", err)
		}
	}
	if k.hub != nil {
		k.hub.Publish(ll.Text)
	}
	return true
}
