//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

var resourceKernel32 = syscall.NewLazyDLL("kernel32.dll")
var getCurrentProcessHandle = resourceKernel32.NewProc("GetCurrentProcess")
var getProcessTimes = resourceKernel32.NewProc("GetProcessTimes")
var getProcessMemoryInformation = resourceKernel32.NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func fileTimeSeconds(v syscall.Filetime) float64 {
	ticks := (uint64(v.HighDateTime) << 32) | uint64(v.LowDateTime)
	return float64(ticks) / 10_000_000
}

// Process CPU seconds and resident working-set bytes. Never enumerates
// other processes or needs administrator privileges.
func readProcessResourceSample() (float64, uint64, string, error) {
	proc, _, _ := getCurrentProcessHandle.Call()
	if proc == 0 {
		return 0, 0, "Windows process working set", errors.New("GetCurrentProcess failed")
	}
	var created, exited, kernel, user syscall.Filetime
	ok, _, e := getProcessTimes.Call(proc, uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		return 0, 0, "Windows process working set", e
	}
	v := processMemoryCounters{}
	v.CB = uint32(unsafe.Sizeof(v))
	ok, _, e = getProcessMemoryInformation.Call(proc, uintptr(unsafe.Pointer(&v)), uintptr(v.CB))
	if ok == 0 {
		return 0, 0, "Windows process working set", e
	}
	return fileTimeSeconds(kernel) + fileTimeSeconds(user), uint64(v.WorkingSetSize), "Windows process working set", nil
}
