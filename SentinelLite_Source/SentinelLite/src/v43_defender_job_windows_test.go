//go:build windows

package main

import (
 "testing"
 "unsafe"
 "os"
 "os/exec"
 "path/filepath"
 "time"
)

func TestSecurityWindowsDefenderJobConfigurationIsFailClosed(t *testing.T){
 // No external process is started. This validates only creation and
 // kill-on-close limit configuration, NOT process-tree lifetime behavior.
 info:=jobExtendedLimitInfo{}
 info.BasicLimitInformation.LimitFlags=0x2000
 if unsafe.Sizeof(info)<unsafe.Sizeof(info.BasicLimitInformation){
  t.Fatal("invalid Job Object structure layout")
 }
 job,err:=newDefenderJob()
 if err!=nil{t.Fatalf("unable to create a kill-on-close Job Object: %v",err)}
 if job.handle==0{t.Fatal("new Job Object has null handle")}
 job.close()
 if job.handle!=0{t.Fatal("Job Object handle did not close")}
}


// Only an inert copy of the Go test process is started. A ready-file
// handshake verifies the helper actually reached its 15-second sleep before
// the Job Object is closed. Windows can report a 0 exit code for a forcibly
// terminated process, so use observed lifetime rather than exit status.
func TestSecurityDefenderJobKillOnCloseTerminatesControlledChild(t *testing.T) {
 if os.Getenv("SENTINELGUARD_CONTROLLED_JOB_CHILD")=="1" {
    ready:=os.Getenv("SENTINELGUARD_JOB_READY_FILE")
    if ready==""{t.Fatal("no ready file configured for isolated test child")}
    if err:=os.WriteFile(ready,[]byte("sleeping"),0600);err!=nil{t.Fatal(err)}
    time.Sleep(15*time.Second)
    return
 }
 ready:=filepath.Join(t.TempDir(),"child.ready")
 job,err:=newDefenderJob()
 if err!=nil{t.Fatalf("create Job Object: %v",err)}
 cmd:=exec.Command(os.Args[0],"-test.run=^TestSecurityDefenderJobKillOnCloseTerminatesControlledChild$")
 cmd.Env=append(os.Environ(),
    "SENTINELGUARD_CONTROLLED_JOB_CHILD=1",
    "SENTINELGUARD_JOB_READY_FILE="+ready)
 configureDefenderBackground(cmd)
 if err:=cmd.Start();err!=nil{job.close();t.Fatalf("start inert test helper: %v",err)}
 if err:=job.assign(cmd.Process.Pid);err!=nil{
   _=cmd.Process.Kill()
   _=cmd.Wait()
   job.close()
   t.Fatalf("assign inert helper to kill-on-close job: %v",err)
 }
 deadline:=time.Now().Add(5*time.Second)
 for {
    if _,err:=os.Stat(ready);err==nil{break}
    if time.Now().After(deadline){
        job.close()
        _=cmd.Process.Kill()
        _=cmd.Wait()
        t.Fatal("test child did not reach the controlled sleeping state")
    }
    time.Sleep(25*time.Millisecond)
 }
 closedAt:=time.Now()
 job.close()
 done:=make(chan error,1)
 go func(){done<-cmd.Wait()}()
 select {
 case err:=<-done:
    if time.Since(closedAt)>5*time.Second{
        t.Fatalf("sleeping helper was not terminated promptly by closing the Job Object (wait error: %v)",err)
    }
 case <-time.After(5*time.Second):
    _=cmd.Process.Kill()
    t.Fatal("Job Object child persisted more than five seconds after job close")
 }
}
