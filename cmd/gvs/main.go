package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/k37y/gvs/internal/api"
	mcpserver "github.com/k37y/gvs/internal/mcp"
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
	if err := api.ValidateTaskConfiguration(); err != nil {
		log.Fatal(err)
	}
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

	mux, err := newHandler(graphCacheDir)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// Start directory cleanup routine
	maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
	defer stopMaintenance()
	go gvs.StartDirectoryCleanupWithContext(maintenanceCtx, api.IsActiveDirectory)
	go api.MaintainTasks(maintenanceCtx)

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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := api.ShutdownTasks(ctx); err != nil {
		log.Printf("Scan shutdown: %v", err)
	}
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

func newHandler(graphCacheDir string) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/graph/", gvs.LogFileAccess(http.StripPrefix("/graph/", http.FileServer(http.Dir(graphCacheDir)))))
	mux.Handle("/", http.FileServer(http.Dir("./site")))
	mux.HandleFunc("/scan", api.LogRequests(api.CORSMiddleware(api.ScanHandler)))
	mux.HandleFunc("/healthz", api.LogRequests(api.CORSMiddleware(api.HealthHandler)))
	mux.HandleFunc("/callgraph", api.LogRequests(api.CORSMiddleware(api.CallgraphHandler)))
	mux.HandleFunc("/status", api.LogRequests(api.CORSMiddleware(api.StatusHandler)))
	mux.HandleFunc("/cancel", api.LogRequests(api.CORSMiddleware(api.CancelHandler)))
	mux.HandleFunc("/progress/", api.LogRequests(api.CORSMiddleware(api.ProgressHandler)))
	if os.Getenv("GVS_MCP") == "1" {
		handler, err := mcpserver.NewHandler(version, api.DefaultTaskBackend{}, strings.Split(os.Getenv("GVS_MCP_ALLOWED_ORIGINS"), ","), os.Getenv("GVS_PUBLIC_URL"))
		if err != nil {
			return nil, err
		}
		mux.Handle("/mcp", handler)
		log.Printf("MCP endpoint enabled at /mcp")
	} else {
		mux.HandleFunc("/mcp", http.NotFound)
	}
	return mux, nil
}
