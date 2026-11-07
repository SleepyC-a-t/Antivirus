//go:build windows

package main

import (
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "syscall"
    "unsafe"

    "golang.org/x/sys/windows"
)

// shellExecuteInfo mirrors SHELLEXECUTEINFOW. Verb "open" deliberately
// preserves the native Windows Shell/AES/MotW execution path, rather than
// bypassing it with CreateProcess or ShellExecuteEx "runas".
type shellExecuteInfo struct {
    cbSize uint32
    mask uint32
    hwnd uintptr
    verb *uint16
    file *uint16
    parameters *uint16
    directory *uint16
    show int32
    hInstApp uintptr
    idList uintptr
    class *uint16
    hkeyClass uintptr
    hotKey uint32
    hIconOrMonitor uintptr
    hProcess windows.Handle
}
var shellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func hashLockedWindowsExecutable(path string)(string,func(),error) {
    p,err:=windows.UTF16PtrFromString(path)
    if err!=nil{return "",nil,err}
    // FILE_SHARE_READ only: prevent write/rename/delete races between the
    // final digest verification and ShellExecuteEx. The handle stays open
    // until the Shell returns. It cannot guard against all filesystem
    // attacks (e.g. filesystem filter drivers), so this is not an absolute
    // identity guarantee.
    h,err:=windows.CreateFile(p,windows.GENERIC_READ,windows.FILE_SHARE_READ,
        nil,windows.OPEN_EXISTING,windows.FILE_ATTRIBUTE_NORMAL,0)
    if err!=nil{return "",nil,fmt.Errorf("cannot acquire read-only review lock: %w",err)}
    file:=os.NewFile(uintptr(h),path)
    closeFn:=func(){_ = file.Close()}
    hash:=sha256.New()
    n,err:=io.Copy(hash,io.LimitReader(file,maxReviewExecutableSize+1))
    if err!=nil{closeFn();return "",nil,err}
    if n>maxReviewExecutableSize{closeFn();return "",nil,errors.New("program exceeds bounded scan size")}
    return hex.EncodeToString(hash.Sum(nil)),closeFn,nil
}

// secureLaunchReviewedExecutable reopens with an OS sharing lock, checks that
// the file hash is unchanged, then invokes the Windows Shell ("open" verb).
// It never requests the "runas" verb. However Windows itself may request
// elevation for some executables; don't promise to defeat the UAC policy.
func secureLaunchReviewedExecutable(path,expectedDigest string,size int64) error {
    observed,unlock,err:=hashLockedWindowsExecutable(path)
    if err!=nil{return err}
    defer unlock()
    if subtle.ConstantTimeCompare([]byte(observed),[]byte(expectedDigest))!=1{
        return errors.New("program changed after approval; rerun review")
    }
    full,err:=filepath.Abs(path);if err!=nil{return err}
    verb,_:=windows.UTF16PtrFromString("open")
    target,err:=windows.UTF16PtrFromString(full);if err!=nil{return err}
    dir,err:=windows.UTF16PtrFromString(filepath.Dir(full));if err!=nil{return err}
    const seeMaskNoAsync=0x100
    const seeMaskNoCloseProcess=0x40
    info:=shellExecuteInfo{
        mask:seeMaskNoAsync|seeMaskNoCloseProcess,
        verb:verb,file:target,directory:dir,show:1,
    }
    info.cbSize=uint32(unsafe.Sizeof(info))
    result,_,callErr:=shellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
    runtime.KeepAlive(info)
    if result==0 {
        return fmt.Errorf("Windows Shell refused the program (security warning, user cancellation, or startup error): %w",callErr)
    }
    if info.hProcess!=0 {_=windows.CloseHandle(info.hProcess)}
    _=size
    return nil
}
func launchReviewedExecutable(path string)error{
    // Legacy test compatibility; normal Scan & Run calls the hash-locked
    // function above via decideLaunch, never directly calls this function.
    return errors.New("direct launch is disabled; an approved digest is required")
}
var _=syscall.Errno(0)
