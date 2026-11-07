//go:build windows
package main
import(
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestV42ZoneIdentifierDownloadOriginAndBenignLocal(t *testing.T){
 p:=filepath.Join(t.TempDir(),"safe-example.exe")
 data:=make([]byte,512);copy(data,[]byte("MZ"))
 if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
 zone,internet,err:=v42ZoneIdentifier(p)
 if err!=nil||internet{t.Fatalf("local file must not be an internet download: %q err=%v",zone,err)}
 // This is a harmless NTFS alternate data stream. No payload is executed.
 err=os.WriteFile(p+":Zone.Identifier",[]byte("[ZoneTransfer]\r\nZoneId=3\r\n"),0600)
 if err!=nil{t.Skipf("runner filesystem does not support alternate streams: %v",err)}
 zone,internet,err=v42ZoneIdentifier(p)
 if err!=nil||!internet||!strings.Contains(zone,"ZoneId=3"){
  t.Fatalf("internet Mark-of-the-Web not surfaced: %q err=%v",zone,err)
 }
}
func TestV42AuthenticodeVerificationMetadataNotMisleading(t *testing.T){
 exe:=filepath.Join(os.Getenv("WINDIR"),"System32","notepad.exe")
 if _,err:=os.Stat(exe);err!=nil{t.Skip(err)}
 status,publisher:=v42VerifySignature(exe)
 if status==""||publisher==""{t.Fatal("signature status and publisher must be disclosed, even if unavailable")}
}
