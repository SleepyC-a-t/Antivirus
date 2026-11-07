//go:build windows

package main

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "syscall"
    "time"
    "unsafe"

    "golang.org/x/sys/windows"
)

// WinVerifyTrust generic Authenticode signing policy.
type winTrustFileInfo struct {
 cbStruct uint32
 path *uint16
 hFile windows.Handle
 knownSubject uintptr
}
type winTrustData struct {
 cbStruct uint32
 policyCallback uintptr
 sipClient uintptr
 uiChoice uint32
 revocation uint32
 unionChoice uint32
 fileInfo *winTrustFileInfo
 stateAction uint32
 stateData windows.Handle
 urlRef *uint16
 flags uint32
 uiContext uint32
 signatureSettings uintptr
}
var winVerifyTrust=windows.NewLazySystemDLL("wintrust.dll").NewProc("WinVerifyTrust")
var verifyAction=windows.GUID{Data1:0x00aac56b,Data2:0xcd44,Data3:0x11d0,Data4:[8]byte{0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xee}}
func v42VerifySignature(path string)(string,string){
 name,err:=windows.UTF16PtrFromString(path)
 if err!=nil{return "Could not verify signature: invalid path","Unverified"}
 input:=winTrustFileInfo{path:name}
 input.cbStruct=uint32(unsafe.Sizeof(input))
 data:=winTrustData{uiChoice:2,unionChoice:1,fileInfo:&input,flags:0x1000|0x10}
 data.cbStruct=uint32(unsafe.Sizeof(data))
 status,_,_:=winVerifyTrust.Call(0,uintptr(unsafe.Pointer(&verifyAction)),uintptr(unsafe.Pointer(&data)))
 if uint32(status)!=0 {
     return fmt.Sprintf("Not verified (WinVerifyTrust status 0x%08X)",uint32(status)),"Unverified"
 }
 // Publisher is informational, not a trust decision. Windows' locally cached
 // signature-chain validity is determined by WinVerifyTrust above.
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 escaped:=strings.ReplaceAll(path,"'","''")
 script:="$s=Get-AuthenticodeSignature -LiteralPath '"+escaped+"'; if($s.SignerCertificate){$s.SignerCertificate.Subject}"
 cmd:=exec.CommandContext(ctx,"powershell.exe","-NoProfile","-NonInteractive","-Command",script)
 raw,err:=cmd.Output()
 publisher:="Not available"
 if err==nil && len(raw)<4096 {
   publisher=strings.TrimSpace(string(bytes.TrimSpace(raw)))
   if publisher==""{publisher="Not available"}
 }
 return "Trusted (WinVerifyTrust, offline cache)",publisher
}
func v42ZoneIdentifier(path string)(string,bool,error){
 // Use the Windows Alternate Data Stream, *not* a sidecar file.
 raw,err:=os.ReadFile(path+":Zone.Identifier")
 if errors.Is(err,os.ErrNotExist){return "No Zone.Identifier stream found",false,nil}
 if err!=nil{return "Unable to read Zone.Identifier",false,err}
 src:=strings.ToLower(string(raw))
 for _,line:=range strings.Split(src,"\n"){
   s:=strings.TrimSpace(line)
   switch s{
   case "zoneid=3":return "Internet zone (ZoneId=3)",true,nil
   case "zoneid=4":return "Restricted sites zone (ZoneId=4)",true,nil
   case "zoneid=2":return "Trusted sites zone (ZoneId=2)",false,nil
   case "zoneid=1":return "Local intranet zone (ZoneId=1)",false,nil
   case "zoneid=0":return "Local computer zone (ZoneId=0)",false,nil
   }
 }
 return "Zone.Identifier present, zone not recognized",false,nil
}
var _=syscall.Errno(0)
