//go:build windows

package main

import (
    "os"
    "path/filepath"
    "sync/atomic"
    "testing"
)

// This test is deliberately copied unmodified into both historical and
// patched checkouts by the isolated Windows ETW workflow. The CI workflow
// instruments the entry of v42VerifySignature in each checkout to count
// calls without rewriting its behavior. NO untrusted executables are run.
var forensicSignatureCalls atomic.Int64

func TestForensicFullInspectionReadOnly(t *testing.T) {
    roots:=[]struct{label,path string;limit int}{
        {"Windows/System32",filepath.Join(os.Getenv("WINDIR"),"System32"),2200},
        {"Windows/SysWOW64",filepath.Join(os.Getenv("WINDIR"),"SysWOW64"),1200},
        {"Program Files",os.Getenv("ProgramFiles"),1800},
        {"Program Files x86",os.Getenv("ProgramFiles(x86)"),1000},
        {"Python",os.Getenv("SENTINELGUARD_PYTHON_ROOT"),800},
        {"npm",os.Getenv("SENTINELGUARD_NPM_ROOT"),800},
    }
    files,flags:=0,0
    for _,root:=range roots{
        stats:=v42MeasureBenignRoot(t,root.label,root.path,root.limit)
        files+=stats.scanned
        flags+=stats.flagged
    }
    surveyCalls:=forensicSignatureCalls.Load()
    t.Logf("FORENSIC_SURVEY files=%d flags=%d verifySignatureCalls=%d processID=%d",files,flags,surveyCalls,os.Getpid())

    // A separately labeled signed-file control confirms that the original
    // publisher lookup really spawns powershell.exe even when the chosen
    // benign corpus has no triple-import PE. This is NOT counted as a
    // scanner-triggered signature call.
    testTarget:=filepath.Join(os.Getenv("WINDIR"),"System32","notepad.exe")
    directCalls:=int64(0)
    if _,err:=os.Stat(testTarget);err==nil{
        before:=forensicSignatureCalls.Load()
        result,publisher:=v42VerifySignature(testTarget)
        directCalls=forensicSignatureCalls.Load()-before
        t.Logf("FORENSIC_DIRECT_CONTROL file=Windows/System32/notepad.exe calls=%d trust=%q publisherAvailable=%t",directCalls,result,publisher!="Unverified"&&publisher!="Not available")
    }
    t.Logf("FORENSIC_FINAL surveyCalls=%d directControlCalls=%d total=%d",surveyCalls,directCalls,forensicSignatureCalls.Load())
    if files<1000{t.Fatalf("insufficient surveyed benign corpus: %d",files)}
}
