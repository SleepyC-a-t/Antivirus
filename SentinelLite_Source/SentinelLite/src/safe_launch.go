package main

import (
    "crypto/sha256"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

const maxSafeLaunchFileSize int64 = 256*1024*1024

type SafeLaunchResult struct {
    Path string `json:"path"`
    Score int `json:"score"`
    Decision string `json:"decision"`
    Message string `json:"message"`
    Started bool `json:"started"`
}
type LaunchApproval func(path string, score int, reasons []string) bool
type ProgramLauncher func(path string) error

func launchWindowsProgram(path string) error {
    cmd:=exec.Command(path)
    cmd.Dir=filepath.Dir(path)
    return cmd.Start()
}
func verifyExecutable(path string)(string,os.FileInfo,error){
    if strings.TrimSpace(path)=="" {return "",nil,errors.New("choose a program")}
    abs,err:=filepath.Abs(path);if err!=nil{return "",nil,err}
    if !strings.EqualFold(filepath.Ext(abs),".exe") {
        return "",nil,errors.New("Scan & Run supports .exe programs only; script and shortcut execution is intentionally excluded")
    }
    if !isLocalLaunchPath(abs) {return "",nil,errors.New("network executable paths are not supported by Scan & Run")}
    st,err:=os.Lstat(abs);if err!=nil{return "",nil,err}
    if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink!=0 || isReparse(abs) {
        return "",nil,errors.New("program must be a regular local executable, not a reparse point")
    }
    if st.Size()<=0 || st.Size()>maxSafeLaunchFileSize {
        return "",nil,errors.New("program size is outside the supported 1-byte to 256-MiB range")
    }
    return abs,st,nil
}
func hashVerifiedFile(path string,expected os.FileInfo)([32]byte,error){
    f,err:=os.Open(path);if err!=nil{return [32]byte{},err}
    defer f.Close()
    st,err:=f.Stat();if err!=nil{return [32]byte{},err}
    if !os.SameFile(st,expected) || st.Size()!=expected.Size() ||
       !st.ModTime().Equal(expected.ModTime()) {
        return [32]byte{},errors.New("executable changed before or during inspection")
    }
    h:=sha256.New()
    n,err:=io.Copy(h,io.LimitReader(f,maxSafeLaunchFileSize+1))
    if err!=nil{return [32]byte{},err}
    after,err:=f.Stat();if err!=nil{return [32]byte{},err}
    if n!=expected.Size()||n>maxSafeLaunchFileSize||
        after.Size()!=expected.Size()||!after.ModTime().Equal(expected.ModTime()){
        return [32]byte{},errors.New("executable changed while being inspected")
    }
    var result [32]byte
    copy(result[:],h.Sum(nil))
    return result,nil
}
// safeLaunchProgram only mediates programs launched via SentinelGuard's
// explicit Scan & Run button. It does NOT intercept Explorer double-clicks,
// other processes, service launches or pre-execution Windows kernel callbacks.
func (a *ActiveMonitor) safeLaunchProgram(path string,approve LaunchApproval,launch ProgramLauncher)(SafeLaunchResult,error){
    a.mu.RLock()
    allowed:=a.enabled && a.safeLaunch
    a.mu.RUnlock()
    if !allowed {return SafeLaunchResult{},errors.New("turn ON both live protection and opt-in Scan & Run first")}
    p,st,err:=verifyExecutable(path);if err!=nil{return SafeLaunchResult{},err}
    result:=SafeLaunchResult{Path:p,Decision:"not-started"}
    a.mu.Lock()
    a.launchChecks++
    a.mu.Unlock()
    emit:=func(action,why string){
        a.logLaunchEvent(ActiveEvent{At:time.Now(),Path:p,Action:action,
            Score:result.Score,Reason:why})
    }
    before,err:=hashVerifiedFile(p,st)
    if err!=nil {
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-inspection-failed",err.Error())
        return result,err
    }
    // Windows can only launch actual PE executables through this path.
    // A text file renamed .exe is a suspicious artifact, not a runnable PE.
    fhead,headErr:=os.Open(p)
    var magic [2]byte
    if headErr==nil {
        _,headErr=io.ReadFull(fhead,magic[:])
        fhead.Close()
    }
    if headErr!=nil || magic!=[2]byte{'M','Z'} {
        result.Decision="blocked"
        result.Message="File lacks a valid DOS MZ executable header"
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-invalid-executable","Rejected .exe with no MZ header")
        return result,errors.New(result.Message)
    }
    errorsFound:=[]string{}
    f:=inspectFileProtected(p,st,func(reason string){errorsFound=append(errorsFound,reason)})
    if len(errorsFound)>0 {
        err=fmt.Errorf("cannot complete pre-launch inspection: %s",strings.Join(errorsFound,"; "))
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-inspection-failed",err.Error())
        return result,err
    }
    if f!=nil {
        result.Score=f.Score
        if approve==nil || !approve(p,f.Score,f.Reasons){
            result.Decision="cancelled"
            result.Message="You chose not to run the flagged program"
            a.mu.Lock();a.launchDenied++;a.mu.Unlock()
            emit("launch-denied","User declined heuristic warning: "+strings.Join(f.Reasons,"; "))
            return result,nil
        }
        emit("launch-warning-accepted","User accepted heuristic warning; this is not a guarantee of safety")
    } else {
        // Only an explicit Scan & Run button click reaches this path.
        emit("launch-no-heuristic-finding","No heuristic finding; this is not a guarantee of safety")
    }
    a.mu.RLock()
    stillOn:=a.enabled && a.safeLaunch
    a.mu.RUnlock()
    if !stillOn {
        result.Decision="cancelled"
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-denied","Live protection or Scan & Run was disabled during review")
        return result,nil
    }
    after,err:=hashVerifiedFile(p,st)
    if err!=nil || after!=before {
        if err==nil{err=errors.New("file hash changed while awaiting permission")}
        result.Decision="blocked"
        result.Message="Executable changed during inspection or approval"
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-changed","Launch blocked: "+err.Error())
        return result,err
    }
    if launch==nil {launch=launchWindowsProgram}
    if err:=launch(p);err!=nil {
        result.Decision="failed"
        result.Message="Windows could not start this executable"
        a.mu.Lock();a.launchDenied++;a.mu.Unlock()
        emit("launch-failed",err.Error())
        return result,err
    }
    result.Started=true
    result.Decision="started"
    result.Message="Launch initiated; runtime behavior is not monitored or guaranteed safe"
    a.mu.Lock();a.launchApproved++;a.mu.Unlock()
    emit("launch-started",result.Message)
    return result,nil
}
