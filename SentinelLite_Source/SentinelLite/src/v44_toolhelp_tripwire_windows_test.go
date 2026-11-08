//go:build windows

package main

import (
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

// This integration test starts only another copy of the harmless Go test
// program. It does not execute scanned files or any external sample.
func TestSecurityToolhelpTripwireObservesHarmlessChild(t *testing.T) {
    if os.Getenv("SENTINELGUARD_TOOLHELP_TEST_CHILD")=="1" {
        ready:=os.Getenv("SENTINELGUARD_TOOLHELP_READY")
        if err:=os.WriteFile(ready,[]byte("ready"),0600);err!=nil{t.Fatal(err)}
        time.Sleep(12*time.Second)
        return
    }
    a:=newApp(nil)
    if _,err:=a.begin("heuristic:custom");err!=nil{t.Fatal(err)}
    defer a.finish(nil)
    ready:=filepath.Join(t.TempDir(),"ready")
    cmd:=exec.Command(os.Args[0],"-test.run=^TestSecurityToolhelpTripwireObservesHarmlessChild$")
    cmd.Env=append(os.Environ(),"SENTINELGUARD_TOOLHELP_TEST_CHILD=1","SENTINELGUARD_TOOLHELP_READY="+ready)
    if err:=cmd.Start();err!=nil{t.Fatal(err)}
    defer func(){_ = cmd.Process.Kill();_ = cmd.Wait()}()
    deadline:=time.Now().Add(5*time.Second)
    for {
        if _,err:=os.Stat(ready);err==nil{break}
        if time.Now().After(deadline){t.Fatal("inert test child did not signal readiness")}
        time.Sleep(20*time.Millisecond)
    }
    a.mu.RLock()
    done:=a.resourceDone
    a.mu.RUnlock()
    matched:=false
    for time.Now().Before(deadline) {
        a.sampleChildProcesses(done)
        st,_:=a.snapshot()
        for _,child:=range st.ChildProcessEntries{
            if child.PID==uint32(cmd.Process.Pid) {
                if child.ParentPID!=uint32(os.Getpid()){t.Fatalf("Toolhelp parent process mismatch: %d",child.ParentPID)}
                matched=true
                if !strings.EqualFold(child.Image,filepath.Base(os.Args[0])) {
                    t.Fatalf("process image mismatch: %q",child.Image)
                }
                if st.ChildProcessesObserved<1 || st.ChildProcessWarning=="" {
                    t.Fatalf("heuristic-mode process anomaly was not recorded: %+v",st)
                }
                if st.ChildProcessSampleCount<1 || !st.ChildProcessMonitoringAvailable {
                    t.Fatalf("OS process-sampling evidence missing: %+v",st)
                }
            }
        }
        if matched {break}
        time.Sleep(40*time.Millisecond)
    }
    if !matched {t.Fatalf("Toolhelp32 did not report the harmless child PID %d",cmd.Process.Pid)}
}
