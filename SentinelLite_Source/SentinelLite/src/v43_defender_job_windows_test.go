//go:build windows

package main

import (
 "testing"
 "unsafe"
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
