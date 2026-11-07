//go:build windows

package main

import (
    "fmt"
    "runtime"
    "syscall"
    "unsafe"
)

var fileDialogOle32 = syscall.NewLazyDLL("ole32.dll")
var fileDialogCoInitializeEx = fileDialogOle32.NewProc("CoInitializeEx")
var fileDialogCoUninitialize = fileDialogOle32.NewProc("CoUninitialize")
var fileDialogCoCreateInstance = fileDialogOle32.NewProc("CoCreateInstance")
var fileDialogCoTaskMemFree = fileDialogOle32.NewProc("CoTaskMemFree")

var classFileOpenDialog = syscall.GUID{
    Data1: 0xDC1C5A9C, Data2: 0xE88A, Data3: 0x4DDE,
    Data4: [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7},
}
var iidFileOpenDialog = syscall.GUID{
    Data1: 0xD57C7288, Data2: 0xD4AD, Data3: 0x4768,
    Data4: [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60},
}

// Vtable indexes are zero-based, with the three IUnknown methods first.
// Windows IFileOpenDialog inherits IModalWindow and IFileDialog.
func callFolderCOM(obj unsafe.Pointer, method uintptr, args ...uintptr) uintptr {
    vtable := *(*unsafe.Pointer)(obj)
    fn := *(*uintptr)(unsafe.Add(vtable, method*unsafe.Sizeof(uintptr(0))))
    params := make([]uintptr, 0, 1+len(args))
    params = append(params, uintptr(obj))
    params = append(params, args...)
    result, _, _ := syscall.SyscallN(fn, params...)
    return result
}
func folderHRESULT(hr uintptr, operation string) error {
    if uint32(hr)&0x80000000 != 0 {
        return fmt.Errorf("%s failed (Windows HRESULT 0x%08X)", operation, uint32(hr))
    }
    return nil
}

// Choose a folder through the native Windows Explorer-style Common Item Dialog.
// It runs on a dedicated locked STA thread; the scanner never invokes
// PowerShell, executes files or asks the browser to access local folders.
func chooseScanFolder() (string, error) {return chooseNativeItem(true)}
func chooseScanExecutable() (string,error){return chooseNativeItem(false)}
func chooseNativeItem(folder bool) (string, error) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    const coinitApartmentThreaded = 0x2
    initialized, _, _ := fileDialogCoInitializeEx.Call(0, coinitApartmentThreaded)
    if err := folderHRESULT(initialized, "Initialize Windows folder picker"); err != nil {
        return "", err
    }
    defer fileDialogCoUninitialize.Call()

    var dialog unsafe.Pointer
    const clsctxInprocServer = 0x1
    hr, _, _ := fileDialogCoCreateInstance.Call(
        uintptr(unsafe.Pointer(&classFileOpenDialog)), 0, clsctxInprocServer,
        uintptr(unsafe.Pointer(&iidFileOpenDialog)), uintptr(unsafe.Pointer(&dialog)),
    )
    if err := folderHRESULT(hr, "Create Windows folder picker"); err != nil {
        return "", err
    }
    if dialog == nil { return "", fmt.Errorf("Windows folder picker returned no dialog") }
    defer callFolderCOM(dialog, 2) // IUnknown.Release

    var opts uint32
    if err := folderHRESULT(callFolderCOM(dialog, 10, uintptr(unsafe.Pointer(&opts))), "Read folder picker options"); err != nil {
        return "", err
    }
    const fosPickFolders = 0x20
    const fosFileMustExist = 0x1000
    choiceOptions:=uintptr(0)
    if folder {choiceOptions=fosPickFolders}else{choiceOptions=fosFileMustExist}
    const fosForceFileSystem = 0x40
    const fosPathMustExist = 0x800
    if err := folderHRESULT(callFolderCOM(dialog, 9, uintptr(opts) | choiceOptions | fosForceFileSystem | fosPathMustExist), "Configure folder picker"); err != nil {
        return "", err
    }
    titleText:="Choose a folder for SentinelGuard to scan"
    if !folder {titleText="Select an executable for Scan & Run review"}
    title, err := syscall.UTF16PtrFromString(titleText)
    if err != nil { return "", err }
    if err := folderHRESULT(callFolderCOM(dialog, 17, uintptr(unsafe.Pointer(title))), "Set folder picker title"); err != nil {
        return "", err
    }
    labelText:="Choose folder"
    if !folder {labelText="Review executable"}
    label, err := syscall.UTF16PtrFromString(labelText)
    if err != nil { return "", err }
    if err := folderHRESULT(callFolderCOM(dialog, 18, uintptr(unsafe.Pointer(label))), "Set folder picker button label"); err != nil {
        return "", err
    }
    runtime.KeepAlive(title)
    runtime.KeepAlive(label)

    hr = callFolderCOM(dialog, 3, 0) // IModalWindow.Show
    if uint32(hr) == 0x800704C7 { // HRESULT_FROM_WIN32(ERROR_CANCELLED)
        return "", errFolderPickerCanceled
    }
    if err := folderHRESULT(hr, "Show folder picker"); err != nil {
        return "", err
    }
    var item unsafe.Pointer
    if err := folderHRESULT(callFolderCOM(dialog, 20, uintptr(unsafe.Pointer(&item))), "Read selected folder"); err != nil {
        return "", err
    }
    if item == nil { return "", fmt.Errorf("Windows folder picker returned no selection") }
    defer callFolderCOM(item, 2) // IShellItem.Release

    var stringPtr *uint16
    const sigdnFileSystemPath = 0x80058000
    if err := folderHRESULT(callFolderCOM(item, 5, sigdnFileSystemPath, uintptr(unsafe.Pointer(&stringPtr))), "Resolve selected folder path"); err != nil {
        return "", err
    }
    if stringPtr == nil { return "", fmt.Errorf("Windows folder picker returned an empty path") }
    defer fileDialogCoTaskMemFree.Call(uintptr(unsafe.Pointer(stringPtr)))
    // The standard syscall package exposes UTF16ToString (not the
    // x/sys/windows UTF16PtrToString helper). Read the COM-allocated,
    // NUL-terminated UTF-16 buffer with an explicit length ceiling.
    units := make([]uint16, 0, 260)
    for i := uintptr(0); i < 32768; i++ {
        value := *(*uint16)(unsafe.Add(unsafe.Pointer(stringPtr), i*2))
        if value == 0 { return syscall.UTF16ToString(units), nil }
        units = append(units, value)
    }
    return "", fmt.Errorf("chosen folder path exceeds the supported limit")
}
