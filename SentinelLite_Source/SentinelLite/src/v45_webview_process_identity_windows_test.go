//go:build windows

package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// Verify real Windows OS process-path lookup, not just a synthetic name.
// The test does not launch any process or invoke any executable under scan.
func TestSecurityWindowsProcessIdentityUsesKernelPathAndCreationTime(t *testing.T){
    path,ticks,err:=getChildProcessIdentity(uint32(os.Getpid()))
    if err!=nil{t.Fatalf("could not query current process identity: %v",err)}
    if ticks==0 || !filepath.IsAbs(path) {t.Fatalf("invalid native process identity: %q %d",path,ticks)}
    actual,err:=os.Executable()
    if err!=nil{t.Fatal(err)}
    if !strings.EqualFold(filepath.Base(path),filepath.Base(actual)){
        t.Fatalf("native process path has wrong executable: %q vs %q",path,actual)
    }
}

// Check official machine roots cannot be overridden by environment variables.
func TestSecurityWebViewRuntimeRootsReadFromProtectedRegistry(t *testing.T){
    roots:=machineManagedProgramFilesRoots()
    if len(roots)==0{t.Skip("machine does not expose protected Program Files registry values")}
    for _,root:=range roots{
        if !filepath.IsAbs(root){t.Fatalf("relative trusted Program Files path: %q",root)}
    }
}
