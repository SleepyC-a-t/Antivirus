//go:build !windows

package main

import "os/exec"

// Non-Windows builds keep the existing optional Defender API test semantics.
func configureDefenderBackground(cmd *exec.Cmd) {}
