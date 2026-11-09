//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func isReparse(p string) bool           { return false }
func fixedAndRemovableDrives() []string { return []string{} }
func openLocation(p string) error       { return errors.New("Windows-only feature") }
func openWindowsSecurity() error        { return errors.New("Windows-only feature") }
func reportStartupError(s string)       {}
func defenderEXE() string               { return "" }

var _ = os.ErrNotExist
var _ = filepath.Separator
