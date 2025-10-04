package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
)

func handleConn(conn net.Conn) {
	defer conn.Close()
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		slog.Error("failed to get remote address as TCPAddr")
		return
	}

	br := bufio.NewReader(conn)
	sc := bufio.NewScanner(br)
	for sc.Scan() {
		line := sc.Text()
		handleLogLine(remoteAddr, line)
	}

	if err := sc.Err(); err != nil {
		if err != io.EOF {
			slog.Error("scanner error on connection", "remote_addr", remoteAddr.String(), "error", err)
		}
	}
}

func runListener(ln net.Listener) {
	slog.Info("Starting listener", "address", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("failed to accept connection", "address", ln.Addr().String(), "error", err)
			return
		}
		go handleConn(conn)
	}
}

func runServer(listenPorts []string) error {
	var listeners []net.Listener
	for _, port := range listenPorts {
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%s", port))
		if err != nil {
			slog.Error("failed to start listener", "port", port, "error", err)
			continue
		}
		listeners = append(listeners, ln)
		slog.Info("Listening", "address", ln.Addr().String())
		go runListener(ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("no listeners started, exiting")
	}
	return nil
}
