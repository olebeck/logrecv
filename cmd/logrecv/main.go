package main

import (
	"flag"
	"log/slog"
	"os"
	"strconv"

	"logrecv/internal/logrecv"
)

func main() {
	bind := flag.String("bind", envString("BIND", "0.0.0.0"), "address to bind the listeners to")
	logPort := flag.Int("log-port", envInt("PORT", 3333), "TCP port for incoming device logs")
	httpPort := flag.Int("http-port", envInt("HTTP_PORT", 1339), "HTTP port for the web UI, SSE streams and uploads")
	keylogFile := flag.String("keylog", envString("KEYLOGFILE", "keylog.txt"), "keylog file path (empty disables writing)")
	flag.Parse()

	server, err := logrecv.NewServer(logrecv.Config{
		Bind:       *bind,
		LogPort:    *logPort,
		HTTPPort:   *httpPort,
		KeylogFile: *keylogFile,
	})
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := server.Run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func envString(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		slog.Warn("invalid integer environment variable", "key", key, "value", value, "fallback", fallback)
		return fallback
	}
	return n
}
