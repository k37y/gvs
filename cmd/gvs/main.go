package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/k37y/gvs/internal/api"
	"github.com/k37y/gvs/pkg/cmd/gvs"
)

var (
	port    string = "8082"
	version string
)

// getCacheDir returns the cache directory, respecting XDG_CACHE_HOME
func getCacheDir() string {
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return xdgCache
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".cache")
	}
	return "/tmp"
}

func main() {
	// Check for GVS_PORT environment variable
	if envPort := os.Getenv("GVS_PORT"); envPort != "" {
		log.Printf("Using port from environment variable: %s\n", envPort)
		port = envPort
	}

	// Set up cache directories using XDG-compliant paths
	cacheDir := getCacheDir()
	goCacheDir := filepath.Join(cacheDir, "go-build")
	graphCacheDir := filepath.Join(cacheDir, "gvs", "graph")

	// Only set GOCACHE if not already set
	if os.Getenv("GOCACHE") == "" {
		os.Setenv("GOCACHE", goCacheDir)
	}
	err := os.MkdirAll(goCacheDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create go cache directory: %v", err)
	}

	// Create graph cache directory
	err = os.MkdirAll(graphCacheDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create graph cache directory: %v", err)
	}

	// Export graph cache dir for handlers to use
	os.Setenv("GVS_GRAPH_CACHE", graphCacheDir)

	log.Printf("Using cache directory: %s", cacheDir)
	log.Printf("Graph cache: %s", graphCacheDir)

	http.Handle("/graph/", gvs.LogFileAccess(http.StripPrefix("/graph/", http.FileServer(http.Dir(graphCacheDir)))))
	http.Handle("/", http.FileServer(http.Dir("./site")))
	http.HandleFunc("/scan", api.CORSMiddleware(api.ScanHandler))
	http.HandleFunc("/healthz", api.CORSMiddleware(api.HealthHandler))
	http.HandleFunc("/callgraph", api.CORSMiddleware(api.CallgraphHandler))
	http.HandleFunc("/status", api.CORSMiddleware(api.StatusHandler))
	http.HandleFunc("/progress/", api.CORSMiddleware(api.ProgressHandler))

	srv := &http.Server{Addr: ":" + port}

	// Start directory cleanup routine
	go gvs.StartDirectoryCleanup()

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
