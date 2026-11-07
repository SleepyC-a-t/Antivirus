//go:build windows

package main

import (
    "os"
    "path/filepath"
    "testing"
)

// Independent benign-control smoke test against Windows-runner system files,
// rather than strings authored for SentinelGuard's synthetic benchmark.
// This is NOT an independent malware detection test.
func TestWindowsInstalledSystemExecutableBenignControls(t *testing.T){
    systemRoot:=os.Getenv("SystemRoot")
    if systemRoot=="" {t.Skip("Windows system root is unavailable")}
    candidates:=[]string{
        filepath.Join(systemRoot,"System32","notepad.exe"),
        filepath.Join(systemRoot,"System32","cmd.exe"),
        filepath.Join(systemRoot,"System32","regedit.exe"),
        filepath.Join(systemRoot,"System32","where.exe"),
        filepath.Join(systemRoot,"System32","whoami.exe"),
        filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe"),
        filepath.Join(systemRoot,"explorer.exe"),
    }
    examined,flagged:=0,0
    for _,path:=range candidates{
        info,err:=os.Lstat(path)
        if err!=nil||!info.Mode().IsRegular(){t.Logf("Unreported Windows control: %s: %v",path,err);continue}
        examined++
        if f:=inspectFileProtected(path,info,nil);f!=nil {
            flagged++
            t.Errorf("WINDOWS_INSTALL_BENIGN_FP file=%s score=%d reasons=%v",path,f.Score,f.Reasons)
        }
    }
    if examined<4 {t.Skipf("Only %d known Windows binaries were available",examined)}
    t.Logf("WINDOWS_INSTALL_BENIGN_CONTROL examined=%d flagged=%d",examined,flagged)
}
