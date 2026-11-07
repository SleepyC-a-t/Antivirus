//go:build windows

package main

import (
    "errors"
    "fmt"
    "os"
    "strings"
    "syscall"
    "runtime"
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
// WinVerifyTrust flags: WTD_UI_NONE=2, WTD_REVOKE_NONE=0,
// WTD_CACHE_ONLY_URL_RETRIEVAL=0x1000 and
// WTD_REVOCATION_CHECK_NONE=0x10. This is intentionally an OFFLINE,
 // non-interactive embedded-file signature check. Catalog signatures are not
// resolved; report them unverified rather than silently treating them trusted.
const nativeTrustTimeout = 2500 * time.Millisecond
var nativeTrustSlots = make(chan struct{}, 2)
type nativeTrustAnswer struct{status,publisher string}
func v42VerifySignature(path string)(string,string){
    // WinVerifyTrust is synchronous and Windows does not expose a safe
    // cancellation handle. Bound the caller's wait AND the number of native
    // verifications that can remain stuck; do not leak unlimited goroutines.
    select {
    case nativeTrustSlots<-struct{}{}:
    default:
        return "Not verified (native trust verifier busy; no trust granted)", "Unverified"
    }
    result:=make(chan nativeTrustAnswer,1)
    go func(){
        defer func(){<-nativeTrustSlots}()
        status,publisher:=verifyEmbeddedSignatureOffline(path)
        result<-nativeTrustAnswer{status,publisher}
    }()
    select{
    case r:=<-result: return r.status,r.publisher
    case <-time.After(nativeTrustTimeout):
        return "Not verified (native trust verification exceeded 2.5 s; no trust granted)", "Unverified"
    }
}
func describeWinTrustStatus(status uint32)string{
    switch status {
    case 0x800B0100: return "No embedded signature (catalog signatures not checked)"
    case 0x800B0109: return "Certificate chain has an untrusted root"
    case 0x800B0111: return "Signature explicitly distrusted"
    case 0x800B0004: return "Subject not trusted"
    case 0x80096010: return "Signature digest mismatch"
    case 0x80092013: return "Revocation information unavailable (offline)"
    default: return fmt.Sprintf("WinVerifyTrust error 0x%08X",status)
    }
}
func verifyEmbeddedSignatureOffline(path string)(string,string){
    name,err:=windows.UTF16PtrFromString(path)
    if err!=nil{return "Not verified (invalid path)","Unverified"}
    input:=winTrustFileInfo{path:name}
    input.cbStruct=uint32(unsafe.Sizeof(input))
    data:=winTrustData{uiChoice:2,revocation:0,unionChoice:1,fileInfo:&input,flags:0x1000|0x10}
    data.cbStruct=uint32(unsafe.Sizeof(data))
    // INVALID_HANDLE_VALUE suppresses any owner-window association.
    // Combined with WTD_UI_NONE this prevents signature-verifier dialogs.
    result,_,_:=winVerifyTrust.Call(^uintptr(0),
        uintptr(unsafe.Pointer(&verifyAction)),uintptr(unsafe.Pointer(&data)))
    runtime.KeepAlive(name)
    runtime.KeepAlive(input)
    runtime.KeepAlive(data)
    runtime.KeepAlive(verifyAction)
    if uint32(result)!=0{
        return "Not verified ("+describeWinTrustStatus(uint32(result))+")","Unverified"
    }
    // Native publisher extraction is deliberately deferred until OS tracing
    // and an independent review establish that full scanning is process-safe.
    return "Trusted embedded signature (offline; revocation not checked)",
        "Publisher unavailable (native-only verification)"
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
