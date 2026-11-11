package logrecv

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestHubPublishSubscribe(t *testing.T) {
	hub := NewHub[string]()
	ch, unsubscribe := hub.Subscribe(1)
	defer unsubscribe()

	hub.Publish("hello")

	select {
	case got := <-ch:
		if got != "hello" {
			t.Fatalf("got %q, want %q", got, "hello")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for hub value")
	}
}

func TestLogEventsSSE(t *testing.T) {
	server := &Server{
		logs:    NewHub[LogLine](),
		keylogs: NewHub[string](),
	}
	httpServer := httptest.NewServer(server.routes())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %s, want %d", resp.Status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("got content type %q, want text/event-stream", ct)
	}

	want := LogLine{Source: netip.MustParseAddr("192.168.1.42"), Text: "hello"}
	server.logs.Publish(want)

	scanner := bufio.NewScanner(resp.Body)
	var event string
	var data string
	found := false
	for !found && scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			found = event != "" && data != ""
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("stream ended before a complete event was received")
	}

	if event != "log" {
		t.Fatalf("got event %q, want log", event)
	}

	var got LogLine
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("decode event data: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
