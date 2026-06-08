package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var titleIDRegex = regexp.MustCompile(`^[a-zA-Z0-9]{9}$`)

func elfUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	const prefix = "/elfs/"
	const suffix = ".elf"
	log := slog.With("path", path)

	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		http.Error(w, fmt.Sprintf("Invalid path format. Expected %s{titleid}%s", prefix, suffix), http.StatusBadRequest)
		log.Warn("Received ELF upload request with invalid path format")
		return
	}

	titleidWithExt := strings.TrimPrefix(path, prefix)
	titleid := strings.TrimSuffix(titleidWithExt, suffix)

	if !titleIDRegex.MatchString(titleid) {
		http.Error(w, "Invalid titleid format in path. Expected 9 alphanumeric characters.", http.StatusBadRequest)
		log.Warn("Received ELF upload request with invalid titleid format")
		return
	}

	log.Info("Received ELF upload request")

	saveDir := "./elfs/"
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		log.Error("Failed to create ELF save directory", "error", err)
		http.Error(w, "Internal server error: could not create save directory", http.StatusInternalServerError)
		return
	}

	localFilename := titleid + ".elf"
	localSavePath := filepath.Join(saveDir, localFilename)

	outFile, err := os.Create(localSavePath)
	if err != nil {
		log.Error("Failed to create local file for ELF upload", "error", err)
		http.Error(w, "Internal server error: could not create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	written, err := io.Copy(outFile, r.Body)
	if err != nil {
		log.Error("Failed to save ELF upload data", "error", err)
		http.Error(w, "Internal server error: could not save file data", http.StatusInternalServerError)
		return
	}

	log.Info("Successfully uploaded and saved ELF file", "bytes", written)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Successfully uploaded ELF for TitleID %s\n", titleid)
}
