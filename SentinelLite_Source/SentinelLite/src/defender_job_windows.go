//go:build windows

package main

import (
    "errors"
    "fmt"
    "runtime"
    "sync"
    "syscall"
    "unsafe"
)

// Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. This bounds children
// created by the *explicitly selected* Defender helper; it does NOT control
// MsMpEng.exe (the independent Microsoft Defender service).
// The helper is created suspended, assigned before its primary thread resumes.
type defenderJob struct{mu sync.Mutex; handle syscall.Handle}
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
    runtime.KeepAlive(limits)
    if ok==0{job.close();return nil,fmt.Errorf("could not configure kill-on-close Job Object: %w",e)}
    return job,nil
}
func (j *defenderJob) assign(pid int)error{
    if j==nil{return errors.New("missing Defender job")}
    j.mu.Lock()
    defer j.mu.Unlock()
    if j.handle==0{return errors.New("Defender job already closed")}
    const access=0x0100|0x0001 // PROCESS_SET_QUOTA | PROCESS_TERMINATE
    process,err:=syscall.OpenProcess(access,false,uint32(pid))
    if err!=nil{return fmt.Errorf("open Defender helper process: %w",err)}
    defer syscall.CloseHandle(process)
    ok,_,e:=assignJobProcess.Call(uintptr(j.handle),uintptr(process))
    if ok==0{return fmt.Errorf("AssignProcessToJobObject failed: %w",e)}
    return nil
}
func (j *defenderJob)close(){
    if j==nil{return}
    j.mu.Lock()
    defer j.mu.Unlock()
    if j.handle!=0{_ = syscall.CloseHandle(j.handle);j.handle=0}
}

// THREADENTRY32 layout for Toolhelp32 TH32CS_SNAPTHREAD enumeration.
type defenderThreadEntry struct {
    Size uint32
    Usage uint32
    ThreadID uint32
    OwnerProcessID uint32
    BasePriority int32
    DeltaPriority int32
    Flags uint32
}
var defenderCreateSnapshot=jobKernel.NewProc("CreateToolhelp32Snapshot")
var defenderThreadFirst=jobKernel.NewProc("Thread32First")
var defenderThreadNext=jobKernel.NewProc("Thread32Next")
var defenderOpenThread=jobKernel.NewProc("OpenThread")
var defenderResumeThread=jobKernel.NewProc("ResumeThread")

// Called ONLY AFTER assigning the suspended helper process to the Job Object.
// The thread cannot execute while CREATE_SUSPENDED is in effect. If the
// primary suspended thread cannot be located, the caller kills the process
// and closes the Job Object, without launching the Defender scan.
func resumeDefenderProcess(pid int)error {
    const th32csSnapThread=0x4
    snapshot,_,e:=defenderCreateSnapshot.Call(th32csSnapThread,0)
    if snapshot==^uintptr(0){return fmt.Errorf("thread snapshot failed: %v",e)}
    defer syscall.CloseHandle(syscall.Handle(snapshot))
    entry:=defenderThreadEntry{Size:uint32(unsafe.Sizeof(defenderThreadEntry{}))}
    ok,_,e:=defenderThreadFirst.Call(snapshot,uintptr(unsafe.Pointer(&entry)))
    if ok==0{return fmt.Errorf("Thread32First failed: %v",e)}
    for {
        if entry.OwnerProcessID==uint32(pid) {
            const threadSuspendResume=0x0002
            handle,_,openErr:=defenderOpenThread.Call(threadSuspendResume,0,uintptr(entry.ThreadID))
            if handle==0{return fmt.Errorf("OpenThread failed: %v",openErr)}
            result,_,resumeErr:=defenderResumeThread.Call(handle)
            runtime.KeepAlive(entry)
            _=syscall.CloseHandle(syscall.Handle(handle))
            if result==^uintptr(0){return fmt.Errorf("ResumeThread failed: %v",resumeErr)}
            return nil
        }
        ok,_,e=defenderThreadNext.Call(snapshot,uintptr(unsafe.Pointer(&entry)))
        if ok==0 {return fmt.Errorf("no suspended thread belongs to Defender helper PID %d: %v",pid,e)}
    }
}
