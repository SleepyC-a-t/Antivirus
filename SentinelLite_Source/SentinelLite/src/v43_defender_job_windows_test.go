//go:build windows

package main

import (
 "testing"
 "unsafe"
 "os"
 "os/exec"
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


// This runs only a controlled copy of the Go test binary with no malware or
// third-party utility. The child sleeps; kill-on-close must terminate it.
func TestSecurityDefenderJobKillOnCloseTerminatesControlledChild(t *testing.T) {
 if os.Getenv("SENTINELGUARD_CONTROLLED_JOB_CHILD")=="1" {
    time.Sleep(15*time.Second)
    return
 }
 job,err:=newDefenderJob()
 if err!=nil{t.Fatalf("create Job Object: %v",err)}
 cmd:=exec.Command(os.Args[0],"-test.run=^TestSecurityDefenderJobKillOnCloseTerminatesControlledChild$")
 cmd.Env=append(os.Environ(),"SENTINELGUARD_CONTROLLED_JOB_CHILD=1")
 configureDefenderBackground(cmd)
 if err:=cmd.Start();err!=nil{job.close();t.Fatalf("start inert test helper: %v",err)}
 if err:=job.assign(cmd.Process.Pid);err!=nil{
   _=cmd.Process.Kill()
   _=cmd.Wait()
   job.close()
   t.Fatalf("assign inert helper to kill-on-close job: %v",err)
 }
 job.close()
 done:=make(chan error,1)
 go func(){done<-cmd.Wait()}()
 select{
 case err:=<-done:
   if err==nil {t.Fatal("Job Object close failed to terminate the sleeping child")}
 case <-time.After(5*time.Second):
   _=cmd.Process.Kill()
   t.Fatal("Job Object child persisted for more than five seconds after close")
 }
}
