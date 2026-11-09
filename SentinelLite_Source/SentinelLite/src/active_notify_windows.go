//go:build windows
package main

import (
 "context"
 "log"
 "syscall"
 "time"
 "unsafe"
)
var eventKernel=syscall.NewLazyDLL("kernel32.dll")
var findChange=eventKernel.NewProc("FindFirstChangeNotificationW")
var nextChange=eventKernel.NewProc("FindNextChangeNotification")
var closeChange=eventKernel.NewProc("FindCloseChangeNotification")
var waitChange=eventKernel.NewProc("WaitForSingleObject")

func activeNativeWatcherMode()string{return "Windows change notifications + periodic reconciliation"}
func activeReconcileInterval()time.Duration{return 60*time.Second}
func watchActiveDirectory(ctx context.Context,root string,kick chan<- struct{}){
    name,err:=syscall.UTF16PtrFromString(root);if err!=nil{return}
    const filters=0x1|0x2|0x8|0x10
    handle,_,callErr:=findChange.Call(uintptr(unsafe.Pointer(name)),1,filters)
    if handle==^uintptr(0) || handle==0 {
        log.Printf("Windows directory watcher unavailable: %v",callErr)
        return
    }
    defer closeChange.Call(handle)
    for ctx.Err()==nil {
        code,_,_:=waitChange.Call(handle,900)
        if ctx.Err()!=nil{return}
        if code==0 { // WAIT_OBJECT_0
           select{case kick<-struct{}{}:default:}
           result,_,_:=nextChange.Call(handle)
           if result==0{return}
        }else if code!=0x102 { // WAIT_TIMEOUT
           return
        }
    }
}
