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
	port     string = "8082"
	version  string
	cacheDir = "/tmp/gvs-cache"
)

func main() {
	os.Setenv("GOCACHE", "/tmp/go-build")
	err := os.MkdirAll("/tmp/go-build", os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	http.Handle("/cg/", logFileAccess(http.StripPrefix("/cg/", http.FileServer(http.Dir("/tmp/gvs-cache/img")))))
	http.Handle("/", http.FileServer(http.Dir("./site")))
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/callgraph", callgraphHandler)
	http.HandleFunc("/status", statusHandler)

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
