package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	port    string = "8082"
	version string
)

func main() {
	// Set up cache directory
	os.Setenv("GOCACHE", "/tmp/go-build")
	os.MkdirAll("/tmp/go-build", os.ModePerm)

	// Register handlers
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.Handle("/", http.FileServer(http.Dir("./site")))

	// Create server
	srv := &http.Server{Addr: ":" + port}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting gvs, version %s\n", version)
		log.Printf("Server started on port %s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
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
