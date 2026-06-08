package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
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
)

//go:embed index.html
var indexData []byte

var (
	keylogTxt   *os.File
	keylogMu    sync.Mutex
	keylogDests = make(map[io.Writer]struct{})

	clientRandomRegex = regexp.MustCompile(`CLIENT_RANDOM [a-f\d]{64} [a-f\d]{96}`)
)

type LogLine struct {
	Source netip.Addr
	Text   string
}

var logDestsMu sync.Mutex
var logDests = make(map[string]func(LogLine) error)

func addLogDest(key string, handler func(LogLine) error) {
	logDestsMu.Lock()
	defer logDestsMu.Unlock()
	logDests[key] = handler
}

func sendToDests(ll LogLine) {
	logDestsMu.Lock()
	defer logDestsMu.Unlock()
	for key, dest := range logDests {
		err := dest(ll)
		if err != nil {
			fmt.Printf("dest(%s): %s\n", key, err)
			delete(logDests, key)
		}
	}
}

func addKeylogDest(w io.Writer) {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	keylogDests[w] = struct{}{}
}

func openKeylog() {
	keylogFilename, ok := os.LookupEnv("KEYLOGFILE")
	if !ok {
		keylogFilename = "keylog.txt"
	}
	var err error
	keylogTxt, err = os.OpenFile(keylogFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		slog.Error("failed to open keylog file", "error", err)
		os.Exit(1)
	}
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

func handleLoglineKeylog(ll LogLine) bool {
	clientRandom := clientRandomRegex.FindString(ll.Text)
	if clientRandom == "" {
		return false
	}

	keylogMu.Lock()
	defer keylogMu.Unlock()
	if keylogTxt != nil {
		_, err := fmt.Fprintln(keylogTxt, ll.Text)
		if err != nil {
			slog.Error("failed to write to keylog file", "error", err)
		}
		keylogTxt.Sync()
	}
	for dest := range keylogDests {
		_, err := fmt.Fprintln(dest, ll.Text)
		if err != nil {
			delete(keylogDests, dest)
		}
	}
	return true
}

func handleWs(w http.ResponseWriter, req *http.Request) {
	var upgrader websocket.Upgrader
	c, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		slog.Error("upgrade", "error", err)
		return
	}
	defer c.Close()

	addLogDest(c.RemoteAddr().String(), func(ll LogLine) error {
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
	addLogDest(req.RemoteAddr, writeHandler(w, ch, nil))
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
	addLogDest(req.RemoteAddr, writeHandler(w, ch, func(ll LogLine) bool {
		return ll.Source == ip
	}))
	<-ch
}

func formatLogline(ll LogLine) string {
	id := ll.Source.As4()[3]
	color := id
	return fmt.Sprintf("\x1b[38;5;%dm% 3d\x1b[0m: %s\n", color, id, ll.Text)
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
	fmt.Fprint(os.Stdout, formatLogline(ll))
	sendToDests(ll)
}

func handleLogConn(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		handleLogLine(remoteAddr, line)
	}
	if err := scanner.Err(); err != nil {
		if err != io.EOF {
			slog.Error("scanner error on connection", "addr", remoteAddr.String(), "error", err)
		}
	}
}

func handleKeylogConn(conn net.Conn) {
	defer conn.Close()
	addKeylogDest(conn)
	io.Copy(io.Discard, conn)
}

func handleSendConn(conn net.Conn) {
	defer conn.Close()
	addLogDest(conn.RemoteAddr().String(), func(ll LogLine) error {
		_, err := fmt.Fprint(conn, formatLogline(ll))
		return err
	})
	io.Copy(io.Discard, conn)
}

func runListener(addr, name string, handler func(net.Conn)) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		slog.Error("failed to start listener", "address", addr, "error", err)
		os.Exit(1)
	}
	slog.Info("Listening", "address", ln.Addr().String(), "thing", name)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				slog.Error("failed to accept connection", "address", ln.Addr().String(), "error", err)
				return
			}
			go handler(conn)
		}
	}()
}

func runServer() {
	logPort, ok := os.LookupEnv("PORT")
	if !ok {
		logPort = "3333"
	}
	openKeylog()

	go cleanupCoredumpStates()

	runListener("0.0.0.0:"+logPort, "log", handleLogConn)
	runListener("0.0.0.0:3334", "keylog", handleKeylogConn)
	runListener("0.0.0.0:3335", "send", handleSendConn)

	mux := http.NewServeMux()
	mux.HandleFunc("/elfs/", elfUploadHandler)
	mux.Handle("/", http.RedirectHandler("/index.html", 302))
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, req *http.Request) {
		http.ServeContent(w, req, "index.html", time.Now(), bytes.NewReader(indexData))
	})
	mux.HandleFunc("/ws", handleWs)
	mux.HandleFunc("/log", handleStreamLog)
	mux.HandleFunc("/log/:ip", handleStreamLogIp)

	err := http.ListenAndServe("0.0.0.0:1339", mux)
	if err != nil {
		slog.Error("HTTP server failed", "error", err)
	}
}

func runClient(clientAddr string) {
	openKeylog()
	go func() {
		for {
			conn, err := net.Dial("tcp", clientAddr+":3334")
			if err != nil {
				slog.Error("dial", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}
			_, err = io.Copy(keylogTxt, conn)
			if err != nil {
				slog.Error("copy", "error", err)
			}
			conn.Close()
		}
	}()

	go func() {
		for {
			conn, err := net.Dial("tcp", clientAddr+":3335")
			if err != nil {
				slog.Error("dial", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}
			slog.Info("connected")
			_, err = io.Copy(os.Stdout, conn)
			if err != nil {
				slog.Error("copy", "error", err)
			}
			conn.Close()
		}
	}()
	select {}
}

func main() {
	var clientAddr string
	flag.StringVar(&clientAddr, "client", "", "")
	flag.Parse()

	if clientAddr != "" {
		runClient(clientAddr)
	}

	runServer()
}
