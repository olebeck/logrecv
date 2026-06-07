package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"time"

	_ "embed"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

//go:embed index.html
var indexData []byte

var (
	keylogTxt *os.File
	keylogMu  sync.Mutex

	clientRandomRegex = regexp.MustCompile(`CLIENT_RANDOM [a-f\d]{64} [a-f\d]{96}`)
)

type LogLine struct {
	Source netip.Addr
	Text   string
}

var logDestsMu sync.Mutex
var logDests = make(map[string]func(LogLine) error)

func addDest(key string, handler func(LogLine) error) {
	logDestsMu.Lock()
	logDests[key] = handler
	logDestsMu.Unlock()
}

func sendToDests(ll LogLine) {
	logDestsMu.Lock()
	for key, dest := range logDests {
		err := dest(ll)
		if err != nil {
			fmt.Printf("dest(%s): %s\n", key, err)
			delete(logDests, key)
		}
	}
	logDestsMu.Unlock()
}

func writeHandler(w io.Writer, ch chan struct{}, filter func(ll LogLine) bool) func(ll LogLine) error {
	return func(ll LogLine) error {
		if filter != nil && !filter(ll) {
			return nil
		}
		data, _ := json.Marshal(ll)
		_, err := w.Write(append(data, '\n'))
		if err != nil {
			close(ch)
		}
		return err
	}
}

func stdoutDest(ll LogLine) error {
	id := ll.Source.As4()[3]
	color := id
	logline := fmt.Sprintf("\x1b[38;5;%dm% 3d\x1b[0m: %s\n", color, id, ll.Text)
	fmt.Fprint(os.Stdout, logline)
	return nil
}

func openKeylog(filename string) error {
	var err error
	keylogTxt, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open keylog file: %w", err)
	}
	logrus.Info("Keylog file opened successfully")
	return nil
}

func handleLoglineKeylog(ll LogLine) bool {
	if keylogTxt == nil {
		return false
	}
	clientRandom := clientRandomRegex.FindString(ll.Text)
	if clientRandom == "" {
		return false
	}

	keylogMu.Lock()
	defer keylogMu.Unlock()
	if _, err := keylogTxt.WriteString(ll.Text + "\n"); err != nil {
		logrus.WithError(err).Error("failed to write to keylog file")
	}
	keylogTxt.Sync()
	return true
}

func handleWs(w http.ResponseWriter, req *http.Request) {
	var upgrader websocket.Upgrader
	c, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		logrus.Print("upgrade:", err)
		return
	}
	defer c.Close()

	addDest(c.RemoteAddr().String(), func(ll LogLine) error {
		return c.WriteJSON(ll)
	})

	for {
		_, _, err := c.ReadMessage()
		if err != nil {
			break
		}
	}
}

func handleStreamLog(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	ch := make(chan struct{})
	addDest(req.RemoteAddr, writeHandler(w, ch, nil))
	<-ch
}

func handleStreamLogIp(w http.ResponseWriter, req *http.Request) {
	ip, err := netip.ParseAddr(req.PathValue("ip"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "invalid ip: %s\n", err)
		return
	}
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	ch := make(chan struct{})
	addDest(req.RemoteAddr, writeHandler(w, ch, func(ll LogLine) bool {
		return ll.Source == ip
	}))
	<-ch
}

func handleLogLine(remoteAddr *net.TCPAddr, line string) {
	remoteIP, _ := netip.AddrFromSlice(remoteAddr.IP)
	ll := LogLine{Source: remoteIP, Text: line}

	if handleLogLineCoredump(ll) {
		return
	}
	if handleLoglineKeylog(ll) {
		return
	}
	sendToDests(ll)
}

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

func runServer(address string) error {
	ln, err := net.Listen("tcp4", address)
	if err != nil {
		slog.Error("failed to start listener", "address", address, "error", err)
		return err
	}
	slog.Info("Listening", "address", ln.Addr().String())
	go runListener(ln)
	return nil
}

func main() {
	logPort, ok := os.LookupEnv("PORT")
	if !ok {
		logPort = "3333"
	}

	keylogFilename, ok := os.LookupEnv("KEYLOGFILE")
	if !ok {
		keylogFilename = "keylog.txt"
	}
	if err := openKeylog(keylogFilename); err != nil {
		slog.Error(err.Error())
		return
	}

	go cleanupCoredumpStates()

	mux := http.NewServeMux()
	mux.HandleFunc("/elfs/", elfUploadHandler)
	mux.Handle("/", http.RedirectHandler("/index.html", 302))
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, req *http.Request) {
		http.ServeContent(w, req, "index.html", time.Now(), bytes.NewReader(indexData))
	})
	mux.HandleFunc("/ws", handleWs)
	mux.HandleFunc("/log", handleStreamLog)
	mux.HandleFunc("/log/:ip", handleStreamLogIp)

	addDest("stdout", stdoutDest)

	if err := runServer("0.0.0.0:" + logPort); err != nil {
		slog.Error(err.Error())
		return
	}

	err := http.ListenAndServe("0.0.0.0:1339", mux)
	if err != nil {
		logrus.Error("HTTP server failed", "error", err)
	}
}
