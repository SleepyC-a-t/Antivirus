//go:build windows

package main

import (
	"os"
	"errors"
    "fmt"
	"runtime"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getFileAttributes = kernel32.NewProc("GetFileAttributesW")
var getDriveType = kernel32.NewProc("GetDriveTypeW")
var user32 = syscall.NewLazyDLL("user32.dll")
var messageBox = user32.NewProc("MessageBoxW")

func isReparse(path string) bool {
	u, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attr, _, _ := getFileAttributes.Call(uintptr(unsafe.Pointer(u)))
	return attr != 0xffffffff && (attr&0x400) != 0
}
func fixedAndRemovableDrives() []string {
	out := []string{}
	for c := 'C'; c <= 'Z'; c++ {
		root := string(c) + ":\\"
		p, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(p)))
		if t == 2 || t == 3 {
			if _, err := os.Stat(root); err == nil {
				out = append(out, root)
			}
		}
	}
	return out
}
// Shell item selection is intentionally an explicit UI action, never called
// from the passive scanner. It does not pass a command-line string to explorer.
var shellFolder=windows.NewLazySystemDLL("shell32.dll")
var ilCreateFromPath=shellFolder.NewProc("ILCreateFromPathW")
var ilClone=shellFolder.NewProc("ILClone")
var ilFindLast=shellFolder.NewProc("ILFindLastID")
var ilRemoveLast=shellFolder.NewProc("ILRemoveLastID")
var ilFree=shellFolder.NewProc("ILFree")
var shOpenSelect=shellFolder.NewProc("SHOpenFolderAndSelectItems")
// Native Shell interactions run on a dedicated locked COM STA thread.
// COINIT_APARTMENTTHREADED (0x2) | COINIT_DISABLE_OLE1DDE (0x4).
// Do not call these from passive scanner workers.
func withShellSTA(action func()error)error {
    results:=make(chan error,1)
    go func(){
        runtime.LockOSThread()
        defer runtime.UnlockOSThread()
        const coinitApartmentThreadedDisableOLE1DDE=0x6
        hr,_,_:=fileDialogCoInitializeEx.Call(0,coinitApartmentThreadedDisableOLE1DDE)
        if uint32(hr)&0x80000000!=0{
            results<-fmt.Errorf("Windows Shell COM STA initialization failed (HRESULT 0x%08X)",uint32(hr))
            return
        }
        defer fileDialogCoUninitialize.Call()
        results<-action()
    }()
    return <-results
}
func openLocation(path string)error{
    return withShellSTA(func()error{
        full,err:=filepath.Abs(path);if err!=nil{return err}
        name,err:=windows.UTF16PtrFromString(full);if err!=nil{return err}
        absolute,_,_:=ilCreateFromPath.Call(uintptr(unsafe.Pointer(name)))
        runtime.KeepAlive(name)
        if absolute==0{return errors.New("cannot parse path into a Windows Shell item")}
        defer ilFree.Call(absolute)
        parent,_,_:=ilClone.Call(absolute)
        if parent==0{return errors.New("could not clone Shell folder identifier")}
        defer ilFree.Call(parent)
        ok,_,_:=ilRemoveLast.Call(parent)
        if ok==0{return errors.New("cannot locate parent folder for selected item")}
        child,_,_:=ilFindLast.Call(absolute)
        if child==0{return errors.New("cannot locate selected item")}
        children:=[]uintptr{child}
        hresult,_,_:=shOpenSelect.Call(parent,1,uintptr(unsafe.Pointer(&children[0])),0)
        runtime.KeepAlive(children)
        if int32(hresult)<0{return fmt.Errorf("Windows Shell could not open the containing folder (HRESULT 0x%08X)",uint32(hresult))}
        return nil
    })
}
const seeMaskNoAsyncForSecurity = 0x100 // SEE_MASK_NOASYNC
func openWindowsSecurity()error{
    return withShellSTA(func()error{
        verb,err:=windows.UTF16PtrFromString("open");if err!=nil{return err}
        uri,err:=windows.UTF16PtrFromString("windowsdefender://threat/");if err!=nil{return err}
        info:=shellExecuteInfo{mask:seeMaskNoAsyncForSecurity,verb:verb,file:uri,show:1}
        info.cbSize=uint32(unsafe.Sizeof(info))
        result,_,callErr:=shellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
        runtime.KeepAlive(verb)
        runtime.KeepAlive(uri)
        runtime.KeepAlive(info)
        if result==0{return fmt.Errorf("Windows Shell refused security-center navigation: %w",callErr)}
        if info.hProcess!=0{_ = windows.CloseHandle(info.hProcess)}
        return nil
    })
}
func reportStartupError(err string) {
	title, _ := syscall.UTF16PtrFromString("SentinelGuard - error")
	body, _ := syscall.UTF16PtrFromString(err)
	messageBox.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}
func defenderEXE() string {
	roots := []string{filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows Defender", "Platform")}
	for _, root := range roots {
		ents, err := os.ReadDir(root)
		if err == nil {
			versions := []string{}
			for _, e := range ents {
				if e.IsDir() {
					versions = append(versions, e.Name())
				}
			}
			// lexical versions are fine for all current Defender platform branches.
			for i := 0; i < len(versions); i++ {
				for j := i + 1; j < len(versions); j++ {
					if strings.Compare(versions[i], versions[j]) < 0 {
						versions[i], versions[j] = versions[j], versions[i]
					}
				}
			}
			for _, ver := range versions {
				path := filepath.Join(root, ver, "MpCmdRun.exe")
				if st, err := os.Stat(path); err == nil && !st.IsDir() {
					return path
				}
			}
		}
	}
	p := filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}
