//go:build windows
package main
import("os";"path/filepath";"strings";"testing")
func TestV42ZoneIdentifierAndNonWritableLaunchLock(t *testing.T){
 p:=filepath.Join(t.TempDir(),"harmless.exe")
 b:=make([]byte,512);copy(b,[]byte("MZ"))
 if err:=os.WriteFile(p,b,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(p+":Zone.Identifier",[]byte("[ZoneTransfer]\r\nZoneId=3\r\n"),0600);err!=nil{t.Skipf("test volume lacks ADS: %v",err)}
 zone,err:=executableZone(p)
 if err!=nil||!strings.Contains(zone,"Internet"){t.Fatalf("MOTW lost: zone=%q err=%v",zone,err)}
 if err:=withLaunchFileLock(p,func()error{
   // A write request must be rejected while a read-only shared handle is held.
   f,err:=os.OpenFile(p,os.O_WRONLY,0)
   if err==nil{f.Close();t.Fatal("file was write-opened inside verified launch lock")}
   return nil
 });err!=nil{t.Fatal(err)}
}
