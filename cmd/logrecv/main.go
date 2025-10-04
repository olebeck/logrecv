package main

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

//go:embed index.html
var indexData []byte

func handleLogLine(remoteAddr *net.TCPAddr, line string) {
	remoteIP, _ := netip.AddrFromSlice(remoteAddr.IP)
	id := remoteIP.As4()[3]

	if handleLogLineKeylog(remoteIP, line) {
		return
	}

	if handleLogLineCoredump(remoteIP, line) {
		return
	}

	color := id
	logline := fmt.Sprintf("\x1b[38;5;%dm% 3d\x1b[0m: %s\n", color, id, line)
	fmt.Fprint(os.Stdout, logline)
	sendLoglineWebsocket(logline)
}

func handleLogLineKeylog(remoteIP netip.Addr, line string) bool {
	if clientRandom := clientRandomRegex.FindString(line); clientRandom != "" {
		writeKeylog(line)
		return true
	}
	return false
}

var upgrader = websocket.Upgrader{}
var websocketMu sync.Mutex
var websocketClients = make(map[int]*websocket.Conn)
var websocketCounter int

func sendLoglineWebsocket(logline string) {
	websocketMu.Lock()
	defer websocketMu.Unlock()

	for _, client := range websocketClients {
		err := client.WriteMessage(websocket.TextMessage, []byte(logline))
		if err != nil {
			logrus.Println("write:", err)
			break
		}
	}
}

func handleWs(w http.ResponseWriter, req *http.Request) {
	c, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		logrus.Print("upgrade:", err)
		return
	}
	defer c.Close()

	websocketMu.Lock()
	clientID := websocketCounter
	websocketCounter++
	websocketClients[clientID] = c
	websocketMu.Unlock()

	defer func() {
		websocketMu.Lock()
		defer websocketMu.Unlock()
		delete(websocketClients, clientID)
	}()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		_ = mt
		_ = message
	}
}

func main() {
	portsStr, ok := os.LookupEnv("PORTS")
	if !ok {
		portsStr = "3333"
	}
	listenPorts := strings.Split(portsStr, ",")

	keylogFilename, ok := os.LookupEnv("KEYLOGFILE")
	if !ok {
		keylogFilename = "keylog.txt"
	}

	if err := openKeylog(keylogFilename); err != nil {
		slog.Error(err.Error())
		return
	}

	go cleanupCoredumpStates()

	if err := runServer(listenPorts); err != nil {
		slog.Error(err.Error())
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/elfs/", elfUploadHandler)
	mux.Handle("/", http.RedirectHandler("/index.html", 302))
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, req *http.Request) {
		http.ServeContent(w, req, "index.html", time.Now(), bytes.NewReader(indexData))
	})
	mux.HandleFunc("/ws", handleWs)

	err := http.ListenAndServe("0.0.0.0:3888", mux)
	if err != nil {
		logrus.Error("HTTP server failed", "error", err)
	}
}
