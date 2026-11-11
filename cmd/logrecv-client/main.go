package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"logrecv/internal/logrecv"
)

func main() {
	serverURL := flag.String("server", envString("LOGRECV_SERVER", "http://127.0.0.1:1339"), "logrecv server base URL")
	keylogFile := flag.String("keylog", envString("KEYLOGFILE", "keylog.txt"), "keylog file path (empty disables writing)")
	flag.Parse()

	baseURL := normalizeServerURL(*serverURL)

	var keylog *os.File
	if *keylogFile != "" {
		var err error
		keylog, err = os.OpenFile(*keylogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			slog.Error("failed to open keylog file", "path", *keylogFile, "error", err)
			os.Exit(1)
		}
		defer keylog.Close()
	}

	go followLogs(baseURL + "/events")
	followKeylogs(baseURL+"/keylog", keylog)
}

func followLogs(url string) {
	for {
		err := logrecv.ConsumeSSE(url, func(event, data string) {
			if event != "" && event != "log" {
				return
			}

			var ll logrecv.LogLine
			if err := json.Unmarshal([]byte(data), &ll); err != nil {
				slog.Error("failed to decode log event", "error", err)
				return
			}
			fmt.Fprint(os.Stdout, logrecv.FormatLogline(ll))
		})
		if err != nil {
			slog.Error("log stream disconnected", "url", url, "error", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func followKeylogs(url string, keylog *os.File) {
	for {
		err := logrecv.ConsumeSSE(url, func(event, data string) {
			if event != "" && event != "keylog" {
				return
			}
			if keylog == nil {
				return
			}
			if _, err := fmt.Fprintln(keylog, data); err != nil {
				slog.Error("failed to write keylog line", "error", err)
				return
			}
			if err := keylog.Sync(); err != nil {
				slog.Error("failed to sync keylog file", "error", err)
			}
		})
		if err != nil {
			slog.Error("keylog stream disconnected", "url", url, "error", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func normalizeServerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	return strings.TrimRight(raw, "/")
}

func envString(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
