package api

import (
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	allowedOrigins []string
)

func init() {
	// Read CORS_ALLOWED_ORIGINS environment variable
	// Format: comma-separated list of origins or "*" for all
	// Example: "http://localhost:3000,http://192.168.1.100:8080"
	// Default: empty (same-origin only, no CORS headers)
	originsEnv := os.Getenv("CORS_ALLOWED_ORIGINS")
	if originsEnv == "" {
		log.Printf("CORS disabled (same-origin only). Set CORS_ALLOWED_ORIGINS to enable.")
		return
	}

	if originsEnv == "*" {
		allowedOrigins = []string{"*"}
		log.Printf("CORS enabled for all origins")
	} else {
		origins := strings.Split(originsEnv, ",")
		for _, origin := range origins {
			trimmed := strings.TrimSpace(origin)
			if trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
		log.Printf("CORS enabled for origins: %v", allowedOrigins)
	}
}

// CORSMiddleware adds CORS headers to HTTP responses
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no origins configured, skip CORS headers (same-origin only)
		if len(allowedOrigins) == 0 {
			next(w, r)
			return
		}

		origin := r.Header.Get("Origin")

		// Determine if origin is allowed
		allowedOrigin := ""
		if allowedOrigins[0] == "*" {
			allowedOrigin = "*"
		} else {
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					allowedOrigin = origin
					break
				}
			}
		}

		// Set CORS headers if origin is allowed
		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}
