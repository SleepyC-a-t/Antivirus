//go:build windows
package main
import("os";"path/filepath";"strings";"testing";"time")
func TestV42WindowsLongPathAndRapidNotificationRecovery(t *testing.T){
 base:=t.TempDir()
 // Windows test environments may have long-path support disabled.
 deep:=filepath.Join(base,strings.Repeat("a",90),strings.Repeat("b",90),strings.Repeat("c",90))
 if err:=os.MkdirAll(deep,0700);err!=nil{
    t.Logf("V42_LONG_PATH_UNAVAILABLE: %v",err)
 }else{
    m:=newActiveMonitor(nil);m.watched=[]string{deep}
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    p:=filepath.Join(deep,"safe.txt")
    if err:=os.WriteFile(p,[]byte("inert"),0600);err!=nil{t.Fatal(err)}
    old:=time.Now().Add(-5*time.Second);_ = os.Chtimes(p,old,old)
    m.pollOnce();m.pollOnce()
    if m.snapshot().Inspected!=1{t.Fatalf("supported long path not scanned: %+v",m.snapshot())}
    _ = m.setEnabled(false)
 }
 // Rapid creation makes notifications coalesce; periodic reconciliation
 // must still enumerate all stable files once, without event-buffer assumptions.
 m:=newActiveMonitor(nil);m.watched=[]string{base}
 m.inspect=func(string,os.FileInfo)*Finding{return nil}
 if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
 old:=time.Now().Add(-5*time.Second)
 for i:=0;i<180;i++{
    p:=filepath.Join(base,"rapid-"+itoaV42(i)+".txt")
    if err:=os.WriteFile(p,[]byte("benign"),0600);err!=nil{t.Fatal(err)}
    _=os.Chtimes(p,old,old)
 }
 m.pollOnce();m.pollOnce()
 if m.snapshot().Inspected<180{t.Fatalf("reconciliation missed rapid test files: got %d",m.snapshot().Inspected)}
 _ = m.setEnabled(false)
}
