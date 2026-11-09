//go:build windows

package main

import (
    "os/exec"
    "syscall"
)

// Microsoft Defender is an explicitly selected external scanner, not part of
// SentinelGuard's passive heuristic file inspection. Never allocate a visible
// command prompt for it. Windows child-console suppression is independent
// of whether SentinelGuard itself is built with the windowsgui subsystem.
func configureDefenderBackground(cmd *exec.Cmd) {
    const createNoWindow = 0x08000000 // CREATE_NO_WINDOW
    const createSuspended = 0x00000004 // CREATE_SUSPENDED: assign to Job before execution
    cmd.SysProcAttr = &syscall.SysProcAttr{
        HideWindow: true,
        CreationFlags: createNoWindow | createSuspended,
    }
}
