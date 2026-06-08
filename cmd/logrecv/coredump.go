package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

var (
	coredumpStartRegex = regexp.MustCompile(`.+?\[coredump\] start ID=(.{9})$`)
	coredumpDoneRegex  = regexp.MustCompile(`.+?\[coredump\] done$`)

	coredumpStatesMu sync.Mutex
	coredumpStates   = make(map[netip.Addr]coredumpState)

	coredumpStateTimeout    = 10 * time.Second
	coredumpDoneGracePeriod = 30 * time.Second
)

type coredumpState struct {
	Updated time.Time
	TitleID string
}

func downloadCoredump(remoteIP netip.Addr, titleID string) ([]byte, error) {
	var (
		ftpPort = "1337"
		ftpUser = "anonymous"
		ftpPass = "anonymous"
	)

	ftpAddress := fmt.Sprintf("%s:%s", remoteIP.String(), ftpPort)
	slog.Info("Attempting to connect to FTP for coredump", "title_id", titleID)

	c, err := ftp.Dial(ftpAddress, ftp.DialWithTimeout(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to FTP server %s: %w", ftpAddress, err)
	}
	defer c.Quit()

	if err := c.Login(ftpUser, ftpPass); err != nil {
		return nil, fmt.Errorf("failed to login to FTP server %s: %w", ftpAddress, err)
	}
	slog.Info("Successfully logged in to FTP")

	if err := c.ChangeDir("ux0:data/"); err != nil {
		return nil, err
	}

	type entry struct {
		*ftp.Entry
		prefix string
	}

	var entries []entry
	var find func(dataEntries []*ftp.Entry, prefix string) error
	find = func(dataEntries []*ftp.Entry, prefix string) error {
		for _, ent := range dataEntries {
			if strings.HasPrefix(ent.Name, "fapscore-"+titleID) {
				entries = append(entries, entry{prefix: prefix, Entry: ent})
			}
			if strings.HasPrefix(ent.Name, "psp2core-") {
				entries = append(entries, entry{prefix: prefix, Entry: ent})
			}
			if ent.Name == titleID {
				if err := c.ChangeDir(titleID); err != nil {
					return err
				}
				dataEntries, err := c.List("")
				if err != nil {
					return err
				}
				err = find(dataEntries, prefix+titleID+"/")
				if err := c.ChangeDir(".."); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// get all top level folders/files
	dataEntries, err := c.List("")
	if err != nil {
		return nil, err
	}
	if err = find(dataEntries, ""); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found")
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return b.Time.Compare(a.Time)
	})

	// if its a folder go into the folder and get filename
	var psp2CoreFile string
	newestEntry := entries[0]
	if newestEntry.Type == ftp.EntryTypeFolder {
		if newestEntry.prefix != "" {
			if err := c.ChangeDir(newestEntry.prefix); err != nil {
				return nil, err
			}
		}
		if err := c.ChangeDir(newestEntry.Name); err != nil {
			return nil, err
		}
		fapFiles, err := c.List("")
		if err != nil {
			return nil, err
		}

		for _, ent := range fapFiles {
			if strings.HasPrefix(ent.Name, "psp2core-") {
				psp2CoreFile = ent.Name
				break
			}
		}
	} else {
		psp2CoreFile = newestEntry.Name
	}

	slog.Info("Downloading", "file", psp2CoreFile)
	resp, err := c.Retr(psp2CoreFile)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	coredumpData, err := io.ReadAll(resp)
	if err != nil {
		return nil, err
	}
	return coredumpData, nil
}

func printCoredumpInfo(coredumpData []byte, titleID string) error {
	coredumpName := "coredump.psp2dmp"
	os.WriteFile(coredumpName, coredumpData, 0777)
	defer os.Remove(coredumpName)

	coredumpPath, _ := filepath.Abs(coredumpName)
	elfPath, _ := filepath.Abs("./elfs/" + titleID + ".elf")

	cmd := exec.Command("uv", "run", "vita-parse-core.py", coredumpPath, elfPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir, _ = filepath.Abs("vita-parse-core")
	return cmd.Run()
}

func handleCoredumpDone(remoteIP netip.Addr, titleID string) error {
	coredumpData, err := downloadCoredump(remoteIP, titleID)
	if err != nil {
		return err
	}
	return printCoredumpInfo(coredumpData, titleID)
}

func cleanupCoredumpStates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		coredumpStatesMu.Lock()
		now := time.Now()
		cleanedCount := 0
		for ip, state := range coredumpStates {
			if now.Sub(state.Updated) > coredumpStateTimeout {
				delete(coredumpStates, ip)
				cleanedCount++
			}
		}
		coredumpStatesMu.Unlock()
	}
}

func handleLogLineCoredumpStart(remoteIP netip.Addr, startMatch []string) {
	titleID := startMatch[1]
	slog.Info("Coredump start detected", "addr", remoteIP.String(), "title_id", titleID)

	coredumpStatesMu.Lock()
	coredumpStates[remoteIP] = coredumpState{
		Updated: time.Now(),
		TitleID: titleID,
	}
	coredumpStatesMu.Unlock()
}

func handleLogLineCoredumpDone(remoteIP netip.Addr) {
	log := slog.With("addr", remoteIP.String())
	log.Info("Coredump done detected")

	coredumpStatesMu.Lock()
	state, found := coredumpStates[remoteIP]
	delete(coredumpStates, remoteIP)
	coredumpStatesMu.Unlock()

	if found {
		log := log.With("title_id", state.TitleID)
		if time.Since(state.Updated) <= coredumpDoneGracePeriod {
			log.Info("Processing coredump")
			go func(ip netip.Addr, titleID string) {
				err := handleCoredumpDone(ip, titleID)
				if err != nil {
					log.Error("failed to handle coredump", "error", err)
				}
			}(remoteIP, state.TitleID)
		} else {
			log.Warn("state timed out")
		}
	} else {
		log.Warn("Coredump done received, but no start found")
	}
}

func handleLogLineCoredump(ll LogLine) bool {
	if startMatch := coredumpStartRegex.FindStringSubmatch(ll.Text); len(startMatch) > 1 {
		handleLogLineCoredumpStart(ll.Source, startMatch)
		return false
	}
	if coredumpDoneRegex.MatchString(ll.Text) {
		handleLogLineCoredumpDone(ll.Source)
		return false
	}
	return false
}
