package main

import (
	"log"
	"net/http"
)

func logFileAccess(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Accessed: %s", r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}
