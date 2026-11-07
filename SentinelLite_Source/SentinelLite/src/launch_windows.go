//go:build windows
package main

import (
 "context"
 "encoding/base64"
 "encoding/binary"
 "errors"
 "fmt"
 "os/exec"
 "strings"
 "time"
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
 // Windows Get-AuthenticodeSignature invokes WinVerifyTrust and certificate
 // chain evaluation. Execute only Microsoft's system PowerShell interpreter
 // (NOT the selected program). Strict 4-second timeout, no profile, no
 // shell expansion of an untrusted path. Results are advisory, never safe.
 systemRoot:=os.Getenv("SystemRoot")
 if systemRoot=="" {systemRoot=`C:\Windows`}
 interpreter:=filepath.Join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe")
 if _,err:=os.Stat(interpreter);err!=nil{return "Unavailable (PowerShell missing)","Unknown"}
 encodedPath:=base64.StdEncoding.EncodeToString([]byte(path))
 script:="$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encodedPath+"'));"+
    "$s=Get-AuthenticodeSignature -LiteralPath $p;"+
    "$subject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{'Unknown'};"+
    "Write-Output ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(([string]$s.Status)+'|'+$subject)))"
 words:=make([]uint16,0,len(script))
 for _,r:=range script{words=append(words,uint16(r))}
 bytes:=make([]byte,len(words)*2)
 for i,v:=range words{binary.LittleEndian.PutUint16(bytes[i*2:],v)}
 ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,interpreter,"-NoProfile","-NonInteractive","-EncodedCommand",base64.StdEncoding.EncodeToString(bytes))
 out,err:=cmd.Output()
 if ctx.Err()!=nil{return "Verification timed out","Unknown"}
 if err!=nil{return "Unavailable (signature checker failed)","Unknown"}
 line:=strings.TrimSpace(string(out))
 raw,err:=base64.StdEncoding.DecodeString(line)
 if err!=nil{return "Unavailable (unrecognized response)","Unknown"}
 parts:=strings.SplitN(string(raw),"|",2)
 if len(parts)!=2{return "Unavailable (malformed response)","Unknown"}
 status:=parts[0]
 publisher:=parts[1]
 if len(publisher)>200{publisher=publisher[:200]}
 switch status {
 case "Valid","NotSigned","HashMismatch","NotTrusted","UnknownError","NotSupportedFileFormat":
     return status,publisher
 default:
     return "Unrecognized status: "+status,publisher
 }
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
