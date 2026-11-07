//go:build windows

package main

import (
    "log"
    "syscall"
    "unsafe"
)

var activeKernel32 = syscall.NewLazyDLL("kernel32.dll")
var activeCreateFile = activeKernel32.NewProc("CreateFileW")
var activeReadChanges = activeKernel32.NewProc("ReadDirectoryChangesW")
var activeCancelIo = activeKernel32.NewProc("CancelIoEx")
var activeCloseHandle = activeKernel32.NewProc("CloseHandle")

// Listens to events in a full subtree. A periodic reconciliation remains in
// place because Windows may drop events after buffer overflow or sleep.
func startFileChangeWatcher(roots []string, events chan<- struct{}) func() {
    handles:=[]uintptr{}
    for _,root:=range roots{
        path,err:=syscall.UTF16PtrFromString(root);if err!=nil{continue}
        const fileListDirectory=0x0001
        const shareAll=0x0001|0x0002|0x0004
        const openExisting=3
        const backupSemantics=0x02000000
        h,_,callErr:=activeCreateFile.Call(uintptr(unsafe.Pointer(path)),fileListDirectory,shareAll,0,openExisting,backupSemantics,0)
        if h==^uintptr(0) || h==0 {
            log.Printf("Live watcher cannot subscribe to folder changes %q: %v; reconciliation remains active",root,callErr)
            continue
        }
        handles=append(handles,h)
        go func(handle uintptr){
            buffer:=make([]byte,64*1024)
            const flags=0x0001|0x0002|0x0008|0x0010|0x0040
            for {
                var written uint32
                ok,_,_:=activeReadChanges.Call(handle,
                    uintptr(unsafe.Pointer(&buffer[0])),uintptr(len(buffer)),
                    1,flags,uintptr(unsafe.Pointer(&written)),0,0)
                if ok==0{return}
                select{case events<-struct{}{}:default:}
            }
        }(h)
    }
    return func(){
        for _,h:=range handles {
            activeCancelIo.Call(h,0)
            activeCloseHandle.Call(h)
        }
    }
}
