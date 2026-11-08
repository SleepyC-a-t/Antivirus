//go:build !windows

package main

// The Windows Toolhelp32 tripwire is not available on other operating systems;
// do not silently imply that an empty result means monitoring succeeded.
func sampleDirectChildProcesses() ([]ObservedChildProcess, bool, error) {
    return nil, false, nil
}
