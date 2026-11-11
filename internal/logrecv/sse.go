package logrecv

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const sseKeepAlive = 15 * time.Second

func streamEvents[T any](
	w http.ResponseWriter,
	r *http.Request,
	event string,
	ch <-chan T,
	encode func(T) ([]byte, error),
	filter func(T) bool,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	ticker := time.NewTicker(sseKeepAlive)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case value, ok := <-ch:
			if !ok {
				return
			}
			if filter != nil && !filter(value) {
				continue
			}

			data, err := encode(value)
			if err != nil {
				slog.Error("failed to encode SSE event", "event", event, "error", err)
				continue
			}

			if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
				return
			}
			for line := range strings.Lines(string(data)) {
				if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
					return
				}
			}
			if _, err := w.Write([]byte{'\n'}); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// consumeSSE reads an SSE stream and calls handle for every dispatched event.
func ConsumeSSE(url string, handle func(event, data string)) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event string
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(data) > 0 {
				handle(event, strings.Join(data, "\n"))
			}
			event = ""
			data = data[:0]
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}

		field, value, found := strings.Cut(line, ":")
		if found {
			value = strings.TrimPrefix(value, " ")
		}
		switch field {
		case "event":
			event = value
		case "data":
			data = append(data, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}
