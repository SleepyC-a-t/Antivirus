//go:build windows

package main

import (
    "errors"
    "fmt"
    "syscall"
    "unsafe"
)

// Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. This bounds children
// created by the *explicitly selected* Defender helper; it does NOT control
// MsMpEng.exe (the independent Microsoft Defender service).
// A small Start -> Assign race remains and is reported explicitly.
type defenderJob struct{handle syscall.Handle}
type jobBasicLimitInfo struct{
    PerProcessUserTimeLimit int64
    PerJobUserTimeLimit int64
    LimitFlags uint32
    MinimumWorkingSetSize uintptr
    MaximumWorkingSetSize uintptr
    ActiveProcessLimit uint32
    Affinity uintptr
    PriorityClass uint32
    SchedulingClass uint32
}
type jobIOCounters struct {
    ReadOperationCount uint64
    WriteOperationCount uint64
    OtherOperationCount uint64
    ReadTransferCount uint64
    WriteTransferCount uint64
    OtherTransferCount uint64
}
type jobExtendedLimitInfo struct {
    BasicLimitInformation jobBasicLimitInfo
    IoInfo jobIOCounters
    ProcessMemoryLimit uintptr
    JobMemoryLimit uintptr
    PeakProcessMemoryUsed uintptr
    PeakJobMemoryUsed uintptr
}
var jobKernel=syscall.NewLazyDLL("kernel32.dll")
var createJobObject=jobKernel.NewProc("CreateJobObjectW")
var setJobInfo=jobKernel.NewProc("SetInformationJobObject")
var assignJobProcess=jobKernel.NewProc("AssignProcessToJobObject")

func newDefenderJob()(*defenderJob,error){
    raw,_,e:=createJobObject.Call(0,0)
    if raw==0{return nil,fmt.Errorf("CreateJobObjectW failed: %w",e)}
    job:=&defenderJob{handle:syscall.Handle(raw)}
    limits:=jobExtendedLimitInfo{}
    limits.BasicLimitInformation.LimitFlags=0x2000
    ok,_,e:=setJobInfo.Call(raw,9,uintptr(unsafe.Pointer(&limits)),unsafe.Sizeof(limits))
    if ok==0{job.close();return nil,fmt.Errorf("could not configure kill-on-close Job Object: %w",e)}
    return job,nil
}
func (j *defenderJob) assign(pid int)error{
    if j==nil||j.handle==0{return errors.New("missing Defender job")}
    const access=0x0100|0x0001 // PROCESS_SET_QUOTA | PROCESS_TERMINATE
    process,err:=syscall.OpenProcess(access,false,uint32(pid))
    if err!=nil{return fmt.Errorf("open Defender helper process: %w",err)}
    defer syscall.CloseHandle(process)
    ok,_,e:=assignJobProcess.Call(uintptr(j.handle),uintptr(process))
    if ok==0{return fmt.Errorf("AssignProcessToJobObject failed: %w",e)}
    return nil
}
func (j *defenderJob)close(){
    if j!=nil&&j.handle!=0{_ = syscall.CloseHandle(j.handle);j.handle=0}
}
