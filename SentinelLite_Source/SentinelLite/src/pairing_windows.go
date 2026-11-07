//go:build windows
package main
import(
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "unsafe"
 "golang.org/x/sys/windows"
)
func pairFilePath()(string,error){
 dir:=os.Getenv("LOCALAPPDATA");if dir==""{return "",errors.New("LOCALAPPDATA unavailable")}
 return filepath.Join(dir,"SentinelLite","browser-pair.dpapi"),nil
}
func protectPair(raw []byte)([]byte,error){
 if len(raw)==0{return nil,errors.New("empty token")}
 in:=windows.DataBlob{Size:uint32(len(raw)),Data:&raw[0]}
 var out windows.DataBlob
 if err:=windows.CryptProtectData(&in,nil,nil,0,nil,0x1,&out);err!=nil{return nil,err}
 defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
 return append([]byte(nil),unsafe.Slice(out.Data,int(out.Size))...),nil
}
func unprotectPair(blob []byte)([]byte,error){
 if len(blob)==0{return nil,errors.New("empty credential")}
 in:=windows.DataBlob{Size:uint32(len(blob)),Data:&blob[0]}
 var out windows.DataBlob
 if err:=windows.CryptUnprotectData(&in,nil,nil,0,nil,0x1,&out);err!=nil{return nil,err}
 defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
 return append([]byte(nil),unsafe.Slice(out.Data,int(out.Size))...),nil
}
func storeProtectedPairingToken(token string)error{
 path,err:=pairFilePath();if err!=nil{return err}
 encrypted,err:=protectPair([]byte(token));if err!=nil{return err}
 if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
 temp:=path+".new"
 if err:=os.WriteFile(temp,encrypted,0600);err!=nil{return err}
 if err:=os.Rename(temp,path);err!=nil{
   if err:=os.Remove(path);err!=nil{return fmt.Errorf("replace pairing credential: %w",err)}
   if err:=os.Rename(temp,path);err!=nil{return err}
 }
 return nil
}
func loadProtectedPairingToken()(string,bool,error){
 path,err:=pairFilePath();if err!=nil{return "",false,err}
 b,err:=os.ReadFile(path)
 if err==nil{
   clear,err:=unprotectPair(b);if err!=nil{return "",false,err}
   if len(clear)!=43{return "",false,errors.New("invalid stored token length")}
   return string(clear),true,nil
 }
 if !os.IsNotExist(err){return "",false,err}
 token,err:=freshPairingToken();if err!=nil{return "",false,err}
 if err:=storeProtectedPairingToken(token);err!=nil{return "",false,err}
 return token,true,nil
}
func rotateProtectedPairingToken()(string,error){
 t,err:=freshPairingToken();if err!=nil{return "",err}
 if err:=storeProtectedPairingToken(t);err!=nil{return "",err}
 return t,nil
}
