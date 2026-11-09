package main

import(
 "fmt"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func TestV42LiveBurstNeverDropsUninspectedDownloads(t *testing.T){
 dir:=t.TempDir()
 m:=newActiveMonitor(nil)
 m.watched=[]string{dir}
 if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
 if m.snapshot().AutoQuarantine {t.Fatal("autoblock enabled by default")}
 older:=time.Now().Add(-8*time.Second)
 const count=220
 for i:=0;i<count;i++{
  p:=filepath.Join(dir,fmt.Sprintf("benign-%03d.txt",i))
  if err:=os.WriteFile(p,[]byte("inert harmless text"),0600);err!=nil{t.Fatal(err)}
  if err:=os.Chtimes(p,older,older);err!=nil{t.Fatal(err)}
 }
 for i:=0;i<10;i++{m.pollOnce()}
 status:=m.snapshot()
 if status.Inspected!=count {
   t.Fatalf("burst lost files: inspected=%d expected=%d pending=%d",status.Inspected,count,len(m.pending))
 }
 if status.Flagged!=0||status.Quarantined!=0{t.Fatalf("benign burst caused unexpected action: %+v",status)}
 if err:=m.setEnabled(false);err!=nil{t.Fatal(err)}
 later:=filepath.Join(dir,"off-control.txt")
 if err:=os.WriteFile(later,[]byte("inert"),0600);err!=nil{t.Fatal(err)}
 for i:=0;i<3;i++{m.pollOnce()}
 if m.snapshot().Inspected!=count{t.Fatal("live OFF did not disable scanning")}
}
func TestV42BrowserPartialDownloadsNotInspectedUntilRename(t *testing.T){
 dir:=t.TempDir()
 m:=newActiveMonitor(nil);m.watched=[]string{dir}
 if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
 for _,suffix:=range []string{".crdownload",".part"}{
  before:=m.snapshot().Inspected
  p:=filepath.Join(dir,"inert"+suffix)
  if err:=os.WriteFile(p,[]byte("harmless"),0600);err!=nil{t.Fatal(err)}
  older:=time.Now().Add(-8*time.Second)
  _=os.Chtimes(p,older,older)
  for i:=0;i<3;i++{m.pollOnce()}
  if m.snapshot().Inspected!=before{t.Fatal("partial browser download inspected prematurely")}
  done:=p+".txt"
  if err:=os.Rename(p,done);err!=nil{t.Fatal(err)}
  _=os.Chtimes(done,older,older)
  m.pollOnce();m.pollOnce()
  if m.snapshot().Inspected!=before+1{t.Fatal("final renamed browser download was not inspected exactly once")}
 }
 if m.snapshot().Inspected!=2 {t.Fatalf("completed download count %d",m.snapshot().Inspected)}
}
