package main

import(
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func TestV42ChurnPartialDownloadRenameAndOff(t *testing.T){
 dir:=t.TempDir()
 m:=newActiveMonitor(nil)
 m.watched=[]string{dir}
 m.inspect=func(p string,st os.FileInfo)*Finding{return nil}
 if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
 // Simulate simultaneous browser temporary downloads without executing data.
 for i:=0;i<200;i++{
    name:=filepath.Join(dir,strings.Repeat("x",8)+"-"+string(rune('a'+i%26))+"-"+itoaV42(i))
    if err:=os.WriteFile(name+".crdownload",[]byte("inert staged test"),0600);err!=nil{t.Fatal(err)}
 }
 m.pollOnce();m.pollOnce()
 if m.snapshot().Inspected!=0{t.Fatal("partial browser downloads must not be inspected")}
 old:=time.Now().Add(-10*time.Second)
 entries,err:=os.ReadDir(dir);if err!=nil{t.Fatal(err)}
 for _,e:=range entries{
    oldName:=filepath.Join(dir,e.Name())
    newName:=strings.TrimSuffix(oldName,".crdownload")+".exe"
    if err:=os.Rename(oldName,newName);err!=nil{t.Fatal(err)}
    if err:=os.Chtimes(newName,old,old);err!=nil{t.Fatal(err)}
 }
 m.pollOnce();m.pollOnce();m.pollOnce()
 if got:=m.snapshot().Inspected;got!=200{t.Fatalf("after 200 completed simulated downloads, inspected %d",got)}
 if err:=m.setEnabled(false);err!=nil{t.Fatal(err)}
 extra:=filepath.Join(dir,"after-off.exe")
 _=os.WriteFile(extra,[]byte("MZ harmless synthetic"),0600)
 m.pollOnce();m.pollOnce()
 if got:=m.snapshot().Inspected;got!=200{t.Fatalf("OFF must stop scanning: got %d",got)}
}
func itoaV42(n int)string{
 if n==0{return "0"}
 r:=""
 for n>0{r=string(rune('0'+n%10))+r;n/=10}
 return r
}
func TestV42WatchedFolderDisappearanceIsReported(t *testing.T){
 root:=t.TempDir()
 p:=filepath.Join(root,"watched")
 if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)}
 m:=newActiveMonitor(nil);m.watched=[]string{p}
 if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
 if err:=os.Remove(p);err!=nil{t.Fatal(err)}
 m.pollOnce()
 if !strings.Contains(m.snapshot().LastError,"Monitor cannot inspect configured folder"){
    t.Fatal("inaccessible monitored folder was silently ignored")
 }
}
