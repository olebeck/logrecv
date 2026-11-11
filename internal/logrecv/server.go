package logrecv

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"
)

//go:embed index.html
var indexData []byte

// Config controls the server's listeners and local output.
type Config struct {
	Bind       string
	LogPort    int
	HTTPPort   int
	KeylogFile string
}

func (c Config) logAddr() string {
	return net.JoinHostPort(c.Bind, strconv.Itoa(c.LogPort))
}

func (c Config) httpAddr() string {
	return net.JoinHostPort(c.Bind, strconv.Itoa(c.HTTPPort))
}

type Server struct {
	cfg     Config
	logs    *Hub[LogLine]
	keylogs *Hub[string]
	keylog  *keylogWriter
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Bind == "" {
		cfg.Bind = "0.0.0.0"
	}

	keylogs := NewHub[string]()
	keylog, err := newKeylogWriter(cfg.KeylogFile, keylogs)
	if err != nil {
		return nil, fmt.Errorf("open keylog file: %w", err)
	}

	return &Server{
		cfg:     cfg,
		logs:    NewHub[LogLine](),
		keylogs: keylogs,
		keylog:  keylog,
	}, nil
}

func (s *Server) Close() error {
	return s.keylog.Close()
}

func (s *Server) Run() error {
	defer s.Close()

	go cleanupCoredumpStates()

	logListener, err := net.Listen("tcp4", s.cfg.logAddr())
	if err != nil {
		return fmt.Errorf("listen for logs on %s: %w", s.cfg.logAddr(), err)
	}
	slog.Info("Listening for logs", "address", logListener.Addr().String())
	go s.acceptLogs(logListener)

	httpServer := &http.Server{
		Addr:              s.cfg.httpAddr(),
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("Listening for HTTP", "address", httpServer.Addr)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server: %w", err)
	}
	return nil
}

func (s *Server) acceptLogs(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("failed to accept log connection", "address", listener.Addr().String(), "error", err)
			return
		}
		go s.handleLogConn(conn)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/elfs/", elfUploadHandler)
	mux.Handle("/", http.RedirectHandler("/index.html", http.StatusFound))
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, req *http.Request) {
		http.ServeContent(w, req, "index.html", time.Now(), bytes.NewReader(indexData))
	})

	mux.HandleFunc("/events", s.handleLogEvents)
	mux.HandleFunc("/events/{ip}", s.handleLogEventsForIP)
	mux.HandleFunc("/keylog", s.handleKeylogEvents)

	return mux
}

func (s *Server) handleLogEvents(w http.ResponseWriter, req *http.Request) {
	ch, unsubscribe := s.logs.Subscribe(256)
	defer unsubscribe()

	streamEvents(w, req, "log", ch, func(ll LogLine) ([]byte, error) {
		return json.Marshal(ll)
	}, nil)
}

func (s *Server) handleLogEventsForIP(w http.ResponseWriter, req *http.Request) {
	ip, err := netip.ParseAddr(req.PathValue("ip"))
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid ip: %s", err), http.StatusBadRequest)
		return
	}

	ch, unsubscribe := s.logs.Subscribe(256)
	defer unsubscribe()

	streamEvents(w, req, "log", ch, func(ll LogLine) ([]byte, error) {
		return json.Marshal(ll)
	}, func(ll LogLine) bool {
		return ll.Source == ip
	})
}

func (s *Server) handleKeylogEvents(w http.ResponseWriter, req *http.Request) {
	ch, unsubscribe := s.keylogs.Subscribe(256)
	defer unsubscribe()

	streamEvents(w, req, "keylog", ch, func(line string) ([]byte, error) {
		return []byte(line), nil
	}, nil)
}

func (s *Server) handleLogLine(remoteAddr *net.TCPAddr, line string) {
	remoteIP, ok := netip.AddrFromSlice(remoteAddr.IP)
	if !ok {
		slog.Error("invalid remote IP", "addr", remoteAddr.String())
		return
	}
	ll := LogLine{Source: remoteIP, Text: line}

	if handleLogLineCoredump(ll) {
		return
	}
	if s.keylog.Handle(ll) {
		return
	}
	fmt.Fprint(os.Stdout, FormatLogline(ll))
	s.logs.Publish(ll)
}

func (s *Server) handleLogConn(conn net.Conn) {
	defer conn.Close()

	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		slog.Error("failed to get remote address as TCPAddr", "addr", conn.RemoteAddr().String())
		return
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		s.handleLogLine(remoteAddr, scanner.Text())
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		slog.Error("scanner error on connection", "addr", remoteAddr.String(), "error", err)
	}
}
