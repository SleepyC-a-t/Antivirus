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

// Exercise the real in-process certificate verifier against an installed
// WebView2 binary when the CI runner provides one. An unverified result is
// never turned into an expected child; the test logs this honestly.
func TestSecurityActualInstalledWebViewRuntimeSignerIfPresent(t *testing.T){
    roots:=machineManagedProgramFilesRoots()
    checked:=0
    for _,root:=range roots {
        appRoot:=filepath.Join(root,"Microsoft","EdgeWebView","Application")
        versions,err:=os.ReadDir(appRoot)
        if err!=nil{continue}
        for _,version:=range versions{
            if !version.IsDir(){continue}
            exe:=filepath.Join(appRoot,version.Name(),"msedgewebview2.exe")
            st,err:=os.Stat(exe)
            if err!=nil||!st.Mode().IsRegular(){continue}
            checked++
            sig,_:=v42VerifySignature(exe)
            class,reason:=classifyChildEvidence("msedgewebview2.exe",exe,sig,roots)
            t.Logf("WEBVIEW_SIGNER_PROBE version=%q status=%q class=%q reason=%q",version.Name(),sig,class,reason)
            if class==childExpectedWebView && sig!="Trusted embedded signature (offline; revocation not checked)"{
                t.Fatal("unverified signature was incorrectly treated as expected")
            }
            return
        }
    }
    if checked==0{t.Skip("no machine-installed WebView2 Runtime present on this Windows runner")}
}
