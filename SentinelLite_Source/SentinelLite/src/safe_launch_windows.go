//go:build windows

package main

import (
    "fmt"
    "strings"
    "syscall"
    "unsafe"
)

// Native Windows Yes/No warning. Default is NO: a missed click must not
// approve an unknown executable. No malware runs during this confirmation.
func confirmProgramLaunch(path string,score int,reasons []string) bool {
    title,_:=syscall.UTF16PtrFromString("SentinelGuard 4.1 — Suspicious program")
    reason:=strings.Join(reasons,"\n")
    if len(reason)>900{reason=reason[:900]+"…"}
    body:=fmt.Sprintf("Potentially unsafe program\n\n%s\n\nHeuristic score: %d\nReasons: %s\n\nA warning is not proof of malware. Opening this file may harm your computer.\n\nRun it anyway?",path,score,reason)
    u,_:=syscall.UTF16PtrFromString(body)
    const yesNo=0x4
    const warning=0x30
    const defaultNo=0x100
    const topmost=0x40000
    result,_,_:=messageBox.Call(0,uintptr(unsafe.Pointer(u)),uintptr(unsafe.Pointer(title)),yesNo|warning|defaultNo|topmost)
    return result==6
}
