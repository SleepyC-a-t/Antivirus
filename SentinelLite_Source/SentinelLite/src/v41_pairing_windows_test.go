//go:build windows
package main
import (
 "os"
 "strings"
 "testing"
)
func TestV41DPAPIPersistedBrowserPairingAndRevocation(t *testing.T){
 temp:=t.TempDir()
 t.Setenv("LOCALAPPDATA",temp)
 first,persisted,err:=loadProtectedPairingToken()
 if err!=nil||!persisted||len(first)!=43{t.Fatalf("DPAPI credential create failed persisted=%v err=%v",persisted,err)}
 repeat,persisted,err:=loadProtectedPairingToken()
 if err!=nil||!persisted||repeat!=first{t.Fatal("pairing not preserved across process-level reload")}
 path,_:=pairFilePath()
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),first){t.Fatal("browser bearer token stored as plaintext")}
 rotated,err:=rotateProtectedPairingToken();if err!=nil||rotated==first{t.Fatalf("token revocation failed: %v",err)}
 again,_,err:=loadProtectedPairingToken()
 if err!=nil||again!=rotated{t.Fatalf("revoked token not durable: %v",err)}
}
func TestV41NativeDirectoryChangeNotifications(t *testing.T){
 if activeNativeWatcherMode()=="" {t.Fatal("no Windows watcher mode")}
}
