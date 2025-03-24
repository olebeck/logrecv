package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
)

var listenPorts []string
var keylogFilename string
var enableMulticast bool

const (
	multicastAddr = "239.0.0.1:12345"
)

var keylogTxt *os.File
var keylogMu sync.Mutex

var clientRandomRegex = regexp.MustCompile(`CLIENT_RANDOM [a-f\d]{64} [a-f\d]{96}`)

func writeKeylog(line string) {
	keylogMu.Lock()
	keylogTxt.WriteString(line + "\n")
	keylogMu.Unlock()
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	id := conn.RemoteAddr().(*net.TCPAddr).IP.To4()[3]

	br := bufio.NewReader(conn)
	sc := bufio.NewScanner(br)
	for sc.Scan() {
		line := sc.Text()
		clientRandom := clientRandomRegex.FindString(line)
		if clientRandom != "" {
			writeKeylog(line)
			continue
		}
		color := id
		fmt.Printf("\x1b[38;5;%dm% 3d\x1b[0m: %s\n", color, id, line)
	}
}

func runListener(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("err: %s\n", err)
			return
		}
		go handleConn(conn)
	}
}

func runMulticastKeyReceiver(iface *net.Interface) {
	log.Printf("[KEYS] using interface %s\n", iface.Name)
	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		log.Fatal(err)
	}

	// Create UDP socket
	conn, err := net.ListenMulticastUDP("udp", iface, addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	err = conn.SetReadBuffer(8192)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	var recentlyReceived = make([]string, 10)
	var recentlyReceivedIndex int
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		sp := bytes.SplitN(buf[:n], []byte("\n"), 2)
		line := string(sp[0])
		clientRandom := clientRandomRegex.FindString(line)
		if clientRandom != "" {
			if slices.Contains(recentlyReceived, line) {
				continue
			}
			recentlyReceived[recentlyReceivedIndex] = line
			recentlyReceivedIndex++
			recentlyReceivedIndex = recentlyReceivedIndex % len(recentlyReceived)
			writeKeylog(line)
		}
	}
}

func getDefaultInterface() (*net.Interface, error) {
	// Use a UDP connection to determine the default route interface
	conn, err := net.Dial("udp", "8.8.8.8:53") // Google's DNS (not actually sending data)
	if err != nil {
		return nil, fmt.Errorf("could not determine default route: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr).IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.Equal(localAddr) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no default interface found")
}

func getMulticastInterface() (*net.Interface, error) {
	multicastIP := os.Getenv("MULTICAST_IFACE")
	if multicastIP != "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}

		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && ipNet.IP.String() == multicastIP {
					return &iface, nil
				}
			}
		}

		return nil, fmt.Errorf("no interface found with IP %s", multicastIP)
	}

	// default interface
	return getDefaultInterface()
}

func parseEnv() error {
	portsStr, ok := os.LookupEnv("PORTS")
	if !ok {
		portsStr = "3333"
	}
	listenPorts = strings.Split(portsStr, ",")

	keylogFilename, ok = os.LookupEnv("KEYLOGFILE")
	if !ok {
		keylogFilename = "keylog.txt"
	}

	withMulticast, ok := os.LookupEnv("WITH_MULTICAST")
	if !ok {
		withMulticast = "true"
	}
	enableMulticast = withMulticast == "true"

	return nil
}

func main() {
	err := parseEnv()
	if err != nil {
		log.Fatal(err)
	}

	keylogTxt, err = os.OpenFile(keylogFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	for _, port := range listenPorts {
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%s", port))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("[LOG] Listening %s\n", ln.Addr().String())
		go runListener(ln)
	}

	if enableMulticast {
		multicastIface, err := getMulticastInterface()
		if err != nil {
			log.Fatal(err)
		}
		go runMulticastKeyReceiver(multicastIface)
	}
	<-ctx.Done()
}
