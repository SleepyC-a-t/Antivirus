package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// Diagnostics are local-only and contain no file content, tokens or hashes.
// The log may contain filesystem paths in panic traces: do not publish it
// without review. Rotation occurs on application startup, limiting growth.
func initDiagnostics() {
	root := os.Getenv("LOCALAPPDATA")
	if root == "" {
		root, _ = os.UserConfigDir()
	}
	if root == "" {
		return
	}
	dir := filepath.Join(root, "SentinelLite", "Logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	path := filepath.Join(dir, "SentinelGuard.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 2*1024*1024 {
		_ = os.Remove(path + ".previous")
		_ = os.Rename(path, path+".previous")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("SentinelGuard v3.3 started at %s", time.Now().Format(time.RFC3339))
}

func panicAsError(v any) error {
	log.Printf("Scanner internal panic: %v\n%s", v, debug.Stack())
	return fmt.Errorf("scanner encountered an internal error (details in local diagnostics log)")
}
