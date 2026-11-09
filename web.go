package main

import (
	"embed"
	"net/http"
	"runtime"
	"strings"
)

//go:embed web/*
var webFS embed.FS

// serveIndex serves the embedded SPA. A tiny asset path check keeps the UI
// served from the single index.html (the app is one page; JS/CSS inline).
func serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui not embedded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func platformName() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

var _ = strings.TrimSpace // (kept for future asset handling)
