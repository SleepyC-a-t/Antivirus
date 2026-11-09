//go:build windows

package main

import (
    "fmt"
    "os"
    "sync"
    "syscall"
    "time"
    "unsafe"
)

const th32csSnapProcess = 0x00000002

// PROCESSENTRY32W is a native Toolhelp32 structure. This is observational
// only: no scanned executable is opened or started.
type processEntry32W struct {
    Size uint32
    Usage uint32
    ProcessID uint32
    DefaultHeapID uintptr
    ModuleID uint32
    Threads uint32
    ParentProcessID uint32
    BasePriority int32
    Flags uint32
    ExeFile [260]uint16
}
var processSnapshotDLL = syscall.NewLazyDLL("kernel32.dll")
var createToolhelp32Snapshot = processSnapshotDLL.NewProc("CreateToolhelp32Snapshot")
var process32FirstW = processSnapshotDLL.NewProc("Process32FirstW")
var process32NextW = processSnapshotDLL.NewProc("Process32NextW")
var hostProcessTimesOnce sync.Once
var hostProcessStartTicks uint64
var hostProcessIdentityError error

func currentHostCreationTicks()(uint64,error){
    hostProcessTimesOnce.Do(func(){
        _,hostProcessStartTicks,hostProcessIdentityError=getChildProcessIdentity(uint32(os.Getpid()))
        if hostProcessStartTicks==0&&hostProcessIdentityError==nil{
            hostProcessIdentityError=fmt.Errorf("Windows did not supply host process creation timestamp")
        }
    })
    return hostProcessStartTicks,hostProcessIdentityError
}


// sampleDirectChildProcesses lists *currently alive* processes with the
// present process PID as their recorded parent. It cannot capture children
// that both start and exit between snapshots. This is a tripwire, NOT ETW.
func sampleDirectChildProcesses() ([]ObservedChildProcess, bool, error) {
    handle, _, callErr := createToolhelp32Snapshot.Call(th32csSnapProcess, 0)
    if handle == ^uintptr(0) {
        return nil, true, fmt.Errorf("Toolhelp32 process snapshot failed: %v", callErr)
    }
    defer syscall.CloseHandle(syscall.Handle(handle))

    var entry processEntry32W
    entry.Size = uint32(unsafe.Sizeof(entry))
    ok, _, firstErr := process32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
    if ok == 0 {
        if errno, yes := firstErr.(syscall.Errno); yes && errno == syscall.ERROR_NO_MORE_FILES {
            return []ObservedChildProcess{}, true, nil
        }
        return nil, true, fmt.Errorf("Process32FirstW failed: %v", firstErr)
    }

    parentID := uint32(os.Getpid())
    out := make([]ObservedChildProcess, 0)
    captured := time.Now()
    for {
        if entry.ParentProcessID == parentID && entry.ProcessID != parentID {
            path,created,identityErr:=getChildProcessIdentity(entry.ProcessID)
            child:=ObservedChildProcess{
                PID: entry.ProcessID,
                ParentPID: parentID,
                Image: syscall.UTF16ToString(entry.ExeFile[:]),
                FirstSeen: captured,
                ExecutablePath: path,
                CreationTimeTicks: created,
            }
            if identityErr!=nil {
                child.IdentityError=identityErr.Error()
            } else if created==0 {
                child.IdentityError="Windows did not provide a child process creation timestamp"
            } else if hostStarted,hostErr:=currentHostCreationTicks();hostErr!=nil{
                child.IdentityError="Could not establish SentinelGuard's own process creation identity: "+hostErr.Error()
            } else if created<hostStarted{
                // A stale parent PID is never enough to classify a child.
                child.IdentityError="Process predates the current SentinelGuard instance (possible parent PID reuse)"
            }
            out=append(out,child)
        }
        ok, _, nextErr := process32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
        if ok == 0 {
            if errno, yes := nextErr.(syscall.Errno); yes && errno == syscall.ERROR_NO_MORE_FILES {
                break
            }
            return nil, true, fmt.Errorf("Process32NextW failed: %v", nextErr)
        }
    }
    return out, true, nil
}
