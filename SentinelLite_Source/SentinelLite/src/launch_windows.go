//go:build windows
package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "syscall"
 "unsafe"
 "golang.org/x/sys/windows"
)

type shellExecuteInfo struct {
 Size uint32
 Mask uint32
 HWND uintptr
 Verb *uint16
 File *uint16
 Parameters *uint16
 Directory *uint16
 Show int32
 Instance uintptr
 IDList uintptr
 Class *uint16
 ClassKey uintptr
 HotKey uint32
 Icon uintptr
 Process windows.Handle
}
var shell32Launch = windows.NewLazySystemDLL("shell32.dll")
var shellExecuteEx = shell32Launch.NewProc("ShellExecuteExW")

// This exclusive read lock blocks writes and rename/delete by other
// processes during the last SHA-256 verification and the shell launch.
func withLaunchFileLock(path string, action func()error)error {
 name,err:=windows.UTF16PtrFromString(path);if err!=nil{return err}
 h,err:=windows.CreateFile(name,windows.GENERIC_READ,windows.FILE_SHARE_READ,
     nil,windows.OPEN_EXISTING,windows.FILE_FLAG_OPEN_REPARSE_POINT,0)
 if err!=nil{return fmt.Errorf("cannot acquire non-writable launch lock: %w",err)}
 defer windows.CloseHandle(h)
 return action()
}
func executableZone(path string)(string,error) {
 f,err:=os.Open(path+":Zone.Identifier")
 if errors.Is(err,os.ErrNotExist){return "No Zone.Identifier (not proof the file is local)",nil}
 if err!=nil{return "Unknown (Zone.Identifier cannot be read)",err}
 defer f.Close()
 b:=make([]byte,4096)
 n,_:=f.Read(b)
 data:=string(b[:n])
 for _,line:=range []string{"ZoneId=4","ZoneId=3","ZoneId=2","ZoneId=1","ZoneId=0"}{
   if containsZoneLine(data,line){
      if line=="ZoneId=3"||line=="ZoneId=4"{return "Downloaded / untrusted Internet zone ("+line+")",nil}
      return "Zone marker present ("+line+")",nil
   }
 }
 return "Zone.Identifier present (unrecognized zone)",nil
}
func containsZoneLine(data,target string)bool {
 for _,line:=range splitZoneLines(data){
  if line==target{return true}
 }
 return false
}
func splitZoneLines(s string)[]string {
 var lines []string
 begin:=0
 for i:=0;i<=len(s);i++{
  if i==len(s)||s[i]=='\n'||s[i]=='\r' {
   if i>begin {lines=append(lines,s[begin:i])}
   begin=i+1
  }
 }
 return lines
}
func verifiedSignatureStatus(path string)(string,string){
 // Authenticode verification requires WinVerifyTrust and publisher certificate
 // chain parsing. Until implemented, never suggest a file is signed/trusted.
 return "Not verified","Not available"
}
func launchReviewedExecutable(path string)error {
 // Never start a child elevated merely because SentinelGuard was started as Administrator.
 var elevated uint32
 var written uint32
 tok:=windows.GetCurrentProcessToken()
 if err:=windows.GetTokenInformation(tok,windows.TokenElevation,(*byte)(unsafe.Pointer(&elevated)),4,&written);err!=nil {
   return fmt.Errorf("cannot determine elevation; refusing to run program: %w",err)
 }
 if elevated!=0 {return errors.New("SentinelGuard was launched elevated: Scan & Run will not start elevated programs")}
 verb,_:=syscall.UTF16PtrFromString("open")
 file,err:=syscall.UTF16PtrFromString(path);if err!=nil{return err}
 dir,err:=syscall.UTF16PtrFromString(filepath.Dir(path));if err!=nil{return err}
 info:=shellExecuteInfo{
   Mask:0x40|0x100|0x4000, // NOCLOSEPROCESS, NOASYNC, UNICODE
   Verb:verb,File:file,Directory:dir,Show:1,
 }
 info.Size=uint32(unsafe.Sizeof(info))
 ok,_,callErr:=shellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
 runtime.KeepAlive(verb);runtime.KeepAlive(file);runtime.KeepAlive(dir)
 if ok==0 {
   return fmt.Errorf("Windows ShellExecuteEx(open) declined or failed: %v",callErr)
 }
 if info.Process!=0{_ = windows.CloseHandle(info.Process)}
 return nil
}
