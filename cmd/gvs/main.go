package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	port string = "8082"
	version string
)

func main() {
	os.Setenv("GOCACHE", "/tmp/go-build")
	os.MkdirAll("/tmp/go-build", os.ModePerm)
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.Handle("/", http.FileServer(http.Dir("./site")))
	fmt.Printf("Starting gvs, version %s\n", version)
	fmt.Printf("Server started on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
