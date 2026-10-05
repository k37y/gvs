package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPRouting(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			t.Setenv("GVS_MCP", map[bool]string{false: "", true: "1"}[enabled])
			t.Setenv("GVS_MCP_ALLOWED_ORIGINS", "")
			t.Setenv("GVS_PUBLIC_URL", "")
			handler, err := newHandler(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := http.StatusNotFound
			if enabled {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("MCP status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != http.StatusOK || rec.Body.String() != "OK" {
				t.Fatalf("REST health changed: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMCPInvalidConfiguration(t *testing.T) {
	t.Setenv("GVS_MCP", "1")
	t.Setenv("GVS_MCP_ALLOWED_ORIGINS", "*")
	if _, err := newHandler(t.TempDir()); err == nil {
		t.Fatal("wildcard origins must fail startup")
	}
}

func TestGetCacheDir_XDG(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/custom/cache")
	t.Setenv("HOME", "/home/user")

	got := getCacheDir()
	if got != "/custom/cache" {
		t.Errorf("getCacheDir() = %q, want /custom/cache", got)
	}
}

func TestGetCacheDir_Home(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "/home/user")

	got := getCacheDir()
	if got != "/home/user/.cache" {
		t.Errorf("getCacheDir() = %q, want /home/user/.cache", got)
	}
}

func TestGetCacheDir_Fallback(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")

	got := getCacheDir()
	if got != "/tmp" {
		t.Errorf("getCacheDir() = %q, want /tmp", got)
	}
}
