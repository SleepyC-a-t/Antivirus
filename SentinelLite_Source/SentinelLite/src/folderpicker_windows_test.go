//go:build windows

package main

import (
    "runtime"
    "syscall"
    "testing"
    "unsafe"
)

// CI cannot click a modal Windows dialog, but this checks that Windows can
// instantiate the Explorer-style COM folder picker and set its native options.
func TestWindowsFolderDialogCOMConfiguration(t *testing.T) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    hr,_,_:=fileDialogCoInitializeEx.Call(0, 2)
    if err:=folderHRESULT(hr,"COM initialization");err!=nil{t.Fatal(err)}
    defer fileDialogCoUninitialize.Call()
    var dialog unsafe.Pointer
    hr,_,_=fileDialogCoCreateInstance.Call(
       uintptr(unsafe.Pointer(&classFileOpenDialog)),0,1,
       uintptr(unsafe.Pointer(&iidFileOpenDialog)),
       uintptr(unsafe.Pointer(&dialog)),
    )
    if err:=folderHRESULT(hr,"COM FileOpenDialog factory");err!=nil{t.Fatal(err)}
    if dialog==nil {t.Fatal("COM returned nil IFileOpenDialog")}
    defer callFolderCOM(dialog,2)
    var opts uint32
    if err:=folderHRESULT(callFolderCOM(dialog,10,uintptr(unsafe.Pointer(&opts))),"GetOptions");err!=nil{t.Fatal(err)}
    if err:=folderHRESULT(callFolderCOM(dialog,9,uintptr(opts|0x20|0x40|0x800)),"SetOptions for folders");err!=nil{t.Fatal(err)}
    title,_:=syscall.UTF16PtrFromString("SentinelGuard test folder selection")
    if err:=folderHRESULT(callFolderCOM(dialog,17,uintptr(unsafe.Pointer(title))),"SetTitle");err!=nil{t.Fatal(err)}
    runtime.KeepAlive(title)
    text,_:=syscall.UTF16PtrFromString("Choose folder")
    if err:=folderHRESULT(callFolderCOM(dialog,18,uintptr(unsafe.Pointer(text))),"SetOkButtonLabel");err!=nil{t.Fatal(err)}
    runtime.KeepAlive(text)
}
