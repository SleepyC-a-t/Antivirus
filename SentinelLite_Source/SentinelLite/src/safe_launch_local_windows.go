//go:build windows

package main

import (
    "path/filepath"
    "syscall"
    "unsafe"
)

// Prevent running a UNC executable or a remotely mapped network drive.
// The static scanner may still inspect network files when separately selected.
func isLocalLaunchPath(path string) bool {
    vol:=filepath.VolumeName(path)
    if len(vol)!=2||vol[1]!=':' {return false}
    root:=vol+"\\"
    wide,err:=syscall.UTF16PtrFromString(root);if err!=nil{return false}
    driveType,_,_:=getDriveType.Call(uintptr(unsafe.Pointer(wide)))
    return driveType==2||driveType==3 // removable or fixed; not network (4)
}
