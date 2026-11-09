//go:build windows

package main

import (
    "fmt"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "unsafe"

    "golang.org/x/sys/windows"
    "golang.org/x/sys/windows/registry"
)

// Native identity observation never executes, opens for write, or launches
// any process. Return unknown if the process disappeared or access was denied.
var processImageDLL = windows.NewLazySystemDLL("kernel32.dll")
var queryFullProcessImageNameW = processImageDLL.NewProc("QueryFullProcessImageNameW")
var getObservedProcessTimes = processImageDLL.NewProc("GetProcessTimes")

type winProcessFiletime struct{
    LowDateTime uint32
    HighDateTime uint32
}

func getChildProcessIdentity(pid uint32)(string,uint64,error){
    h,err:=windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION,false,pid)
    if err!=nil{return "",0,fmt.Errorf("OpenProcess(%d): %w",pid,err)}
    defer windows.CloseHandle(h)
    var created,exited,kernel,user winProcessFiletime
    ok,_,callErr:=getObservedProcessTimes.Call(uintptr(h),
        uintptr(unsafe.Pointer(&created)),uintptr(unsafe.Pointer(&exited)),
        uintptr(unsafe.Pointer(&kernel)),uintptr(unsafe.Pointer(&user)))
    if ok==0{return "",0,fmt.Errorf("GetProcessTimes(%d): %v",pid,callErr)}
    ticks:=uint64(created.HighDateTime)<<32|uint64(created.LowDateTime)

    buf:=make([]uint16,32768)
    n:=uint32(len(buf))
    ok,_,callErr=queryFullProcessImageNameW.Call(
        uintptr(h),0,uintptr(unsafe.Pointer(&buf[0])),uintptr(unsafe.Pointer(&n)))
    runtime.KeepAlive(buf)
    if ok==0 || n==0 || int(n)>len(buf){
        return "",ticks,fmt.Errorf("QueryFullProcessImageNameW(%d): %v",pid,callErr)
    }
    return windows.UTF16ToString(buf[:n]),ticks,nil
}

var trustedProgramRootsOnce sync.Once
var trustedProgramRoots []string

func machineManagedProgramFilesRoots()[]string{
    trustedProgramRootsOnce.Do(func(){
        key,err:=registry.OpenKey(registry.LOCAL_MACHINE,
            `SOFTWARE\Microsoft\Windows\CurrentVersion`,
            registry.QUERY_VALUE|registry.WOW64_64KEY)
        if err!=nil{return}
        defer key.Close()
        for _,valueName:=range []string{"ProgramFilesDir (x86)","ProgramFilesDir"}{
            value,_,err:=key.GetStringValue(valueName)
            if err!=nil||value==""||!filepath.IsAbs(value){continue}
            trustedProgramRoots=append(trustedProgramRoots,filepath.Clean(value))
        }
    })
    return trustedProgramRoots
}

func classifyObservedChildProcess(child ObservedChildProcess) ObservedChildProcess {
    if !strings.EqualFold(child.Image,"msedgewebview2.exe"){
        child.Classification=childUnexpected
        child.ClassificationReason="Not an identified WebView2 UI runtime."
        return child
    }
    // A matching name is never sufficient. Must have a real process image
    // path from the kernel and a signed binary inside an admin-managed root.
    roots:=machineManagedProgramFilesRoots()
    if child.IdentityError!=""{
        child.Classification=childUnverifiedWebView
        child.ClassificationReason="Windows process identity could not be verified: "+child.IdentityError
        return child
    }
    if !isOfficialWebViewRuntimePath(child.ExecutablePath,roots){
        child.Classification,child.ClassificationReason=
            classifyChildEvidence(child.Image,child.ExecutablePath,"Not verified",roots)
        return child
    }
    // Offline/no UI/no PowerShell: the existing strictly native trust probe
    // is reused. It has a bounded caller wait; failure never clears a child.
    sig,_:=v42VerifySignature(child.ExecutablePath)
    child.SignatureStatus=sig
    child.Classification,child.ClassificationReason=
        classifyChildEvidence(child.Image,child.ExecutablePath,sig,roots)
    return child
}

