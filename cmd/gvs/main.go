package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"path/filepath"
	"strings"
)

var (
	port    string = "8082"
	version string
	cacheDir = "/tmp/gvs-cache"
)

func main() {
	os.Setenv("GOCACHE", "/tmp/go-build")
	err := os.MkdirAll("/tmp/go-build", os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.Handle("/", http.FileServer(http.Dir("./site")))

	srv := &http.Server{Addr: ":" + port}

	go func() {
		log.Printf("Starting gvs, version %s\n", version)
		log.Printf("Server started on port %s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Printf("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

func retrieveCacheFromDisk(key string) ([]byte, error) {
	path := filepath.Join(cacheDir, keyToFilename(key))
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return os.ReadFile(path)
	}
	return nil, os.ErrNotExist
}

func saveCacheToDisk(key string, data []byte) error {
	err := os.MkdirAll(cacheDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	return os.WriteFile(filepath.Join(cacheDir, keyToFilename(key)), data, 0644)
}

func keyToFilename(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "/", "_"), ":", "_") + ".json"
}
