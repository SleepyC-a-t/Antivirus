//go:build windows

package main

import (
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
)

// Windows CI safety regression: explicit Defender CLI must not allocate a
// console. No Defender process or scanned executable is started in this test.
func TestSafetyDefenderCommandNeverCreatesConsole(t *testing.T) {
    cmd:=exec.Command("MpCmdRun.exe","-Scan","-ScanType","3")
    configureDefenderBackground(cmd)
    if cmd.SysProcAttr==nil || !cmd.SysProcAttr.HideWindow {
        t.Fatal("Defender command has no hidden-window configuration")
    }
    const createNoWindow=0x08000000
    if cmd.SysProcAttr.CreationFlags&createNoWindow==0{
        t.Fatal("Defender command lacks CREATE_NO_WINDOW flag")
    }
}

// Native WinVerifyTrust inspection must not attempt a PowerShell-based
// publisher lookup. No executable is started or authorized by this test.
func TestSafetyNativeSignatureProbeDoesNotUseInterpreter(t *testing.T) {
    b,err:=os.ReadFile("launch_metadata_windows.go")
    if err!=nil{t.Fatal(err)}
    src:=string(b)
    for _,danger:=range []string{`"os/exec"`,`exec.Command`,`exec.CommandContext`,`"powershell.exe"`,`"cmd.exe"`} {
        if strings.Contains(src,danger) {
            t.Fatalf("native signature metadata can still invoke a child process: %q",danger)
        }
    }
    target:=filepath.Join(os.Getenv("WINDIR"),"System32","notepad.exe")
    if _,err:=os.Stat(target);err!=nil{t.Skip("notepad.exe not present")}
    sig,publisher:=v42VerifySignature(target)
    if sig=="" || publisher=="" {t.Fatal("signature metadata must disclose verification status")}
    if strings.HasPrefix(sig,"Trusted") && !strings.Contains(strings.ToLower(publisher),"unavailable"){
        t.Fatalf("publisher falsely claimed without a native subject parser: %q",publisher)
    }
}
