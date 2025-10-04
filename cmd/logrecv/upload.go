package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
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
	log := logrus.WithField("path", path)

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
		log.WithError(err).Error("Failed to create ELF save directory")
		http.Error(w, "Internal server error: could not create save directory", http.StatusInternalServerError)
		return
	}

	localFilename := titleid + ".elf"
	localSavePath := filepath.Join(saveDir, localFilename)

	outFile, err := os.Create(localSavePath)
	if err != nil {
		log.WithError(err).Error("Failed to create local file for ELF upload")
		http.Error(w, "Internal server error: could not create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	written, err := io.Copy(outFile, r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to save ELF upload data")
		http.Error(w, "Internal server error: could not save file data", http.StatusInternalServerError)
		return
	}

	log.WithField("bytes", written).Info("Successfully uploaded and saved ELF file")

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Successfully uploaded ELF for TitleID %s\n", titleid)
}
