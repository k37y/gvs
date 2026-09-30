package main

import (
	"testing"
)

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
