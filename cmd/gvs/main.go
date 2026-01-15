package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/k37y/gvs/internal/api"
	"github.com/k37y/gvs/pkg/cmd/gvs"
)

var (
	port    string = "8082"
	version string
)

func main() {
	// Check for GVS_PORT environment variable
	if envPort := os.Getenv("GVS_PORT"); envPort != "" {
		log.Printf("Using port from environment variable: %s\n", envPort)
		port = envPort
	}

	os.Setenv("GOCACHE", "/tmp/go-build")
	err := os.MkdirAll("/tmp/go-build", os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	http.Handle("/cg/", gvs.LogFileAccess(http.StripPrefix("/cg/", http.FileServer(http.Dir("/tmp/gvs-cache/img")))))
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
