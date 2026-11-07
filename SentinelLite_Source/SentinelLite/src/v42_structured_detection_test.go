package main

import(
 "archive/zip"
 "bytes"
 "encoding/binary"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "unicode/utf16"
)
func TestV42PERiskPolicyPositiveAndLookalikes(t *testing.T){
 injection:=map[string]bool{"virtualallocex":true,"writeprocessmemory":true,"createremotethread":true}
 score,_:=v42PEIndicators(injection,false,false,false)
 if score<20||score>=40{t.Fatalf("uncorroborated PE imports must be advisory (<40) but nonzero; got %d",score)}
 corroborated,_:=v42PEIndicators(injection,true,false,false)
 if corroborated<40{t.Fatalf("entropy+triad did not exceed 40-point review threshold: %d",corroborated)}
 benign:=[]map[string]bool{
   {"virtualalloc":true,"virtualprotect":true},
   {"virtualallocex":true,"readprocessmemory":true},
   {"writeprocessmemory":true,"virtualallocex":true},
 }
 for _,imports:=range benign{
    v,_:=v42PEIndicators(imports,true,true,true)
    if v!=0{t.Fatalf("weak or ordinary API combination incorrectly flagged: %+v => %d",imports,v)}
 }
 low:=bytes.Repeat([]byte{0},8192)
 if v42SectionEntropy(low)>1{t.Fatal("constant data has high entropy")}
 high:=make([]byte,8192)
 var x uint32=123456789
 for i:=range high{x^=x<<13;x^=x>>17;x^=x<<5;high[i]=byte(x>>16)}
 if v42SectionEntropy(high)<7.55{t.Fatal("uniform pseudo-random sample not high entropy")}
}
func v42TestLink(args,target string,hidden bool)[]byte{
 b:=make([]byte,76)
 binary.LittleEndian.PutUint32(b[0:4],76)
 copy(b[4:20],[]byte{0x01,0x14,0x02,0x00,0,0,0,0,0xc0,0,0,0,0,0,0,0x46})
 binary.LittleEndian.PutUint32(b[20:24],0x8|0x20|0x80) // HasRelativePath, HasArguments, IsUnicode
 if hidden{binary.LittleEndian.PutUint32(b[60:64],7)}else{binary.LittleEndian.PutUint32(b[60:64],1)}
 for _,s:=range []string{target,args}{
  chars:=utf16.Encode([]rune(s))
  tmp:=make([]byte,2+len(chars)*2)
  binary.LittleEndian.PutUint16(tmp[:2],uint16(len(chars)))
  for i,c:=range chars{binary.LittleEndian.PutUint16(tmp[2+i*2:4+i*2],c)}
  b=append(b,tmp...)
 }
 return b
}
func TestV42ShellLinkBinaryParsingPositiveAndBenign(t *testing.T){
 for _,tc:=range []struct{target,args string;hidden,want bool}{
  {"powershell.exe","-EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAA",true,true},
  {"powershell.exe","-NoProfile -Command Write-Output Hello",false,false},
  {"notepad.exe","normal.txt",false,false},
  {"cmd.exe","/c echo normal",true,false},
 }{
  score:=0;reasons:=[]string{}
  inspectV42LNK(v42TestLink(tc.args,tc.target,tc.hidden),&score,&reasons)
  if (score>=40)!=tc.want{t.Fatalf("LNK target=%q args=%q score=%d reasons=%v",tc.target,tc.args,score,reasons)}
 }
 // Plain text with command syntax must not be mistaken for a binary .lnk.
 score:=0;why:=[]string{}
 inspectV42LNK([]byte("powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAA"),&score,&why)
 if score!=0{t.Fatal("plaintext falsely parsed as .lnk")}
}
func TestV42PDFActionsAndBenignLookalikes(t *testing.T){
 samples:=[]struct{file string;content string;want bool}{
  {"active.pdf","%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >>\n2 0 obj <</S /JavaScript /JS (alert(1))>>",true},
  {"launch.pdf","%PDF-1.7\n1 0 obj <</S /Launch /F (setup.exe)>>",true},
  {"ordinary.pdf","%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >>",false},
  {"manual.pdf","%PDF-1.7\nThis manual mentions /JavaScript but contains no /OpenAction",false},
 }
 for _,tc:=range samples{
  score:=0;why:=[]string{}
  inspectV42PDF([]byte(tc.content),&score,&why)
  if (score>=40)!=tc.want{t.Fatalf("%s scored %d reasons=%v",tc.file,score,why)}
 }
}
func v42OfficeZip(t *testing.T,macro []byte)string{
 t.Helper()
 p:=filepath.Join(t.TempDir(),"document.docm")
 f,err:=os.Create(p);if err!=nil{t.Fatal(err)}
 writer:=zip.NewWriter(f)
 a,err:=writer.Create("word/vbaProject.bin");if err!=nil{t.Fatal(err)}
 if _,err=a.Write(macro);err!=nil{t.Fatal(err)}
 if err=writer.Close();err!=nil{t.Fatal(err)}
 if err=f.Close();err!=nil{t.Fatal(err)}
 return p
}
func TestV42MacroPresenceRequiresSuspiciousAutoRunStrings(t *testing.T){
 for _,tc:=range []struct{code string;want bool}{
  {"AutoOpen\x00WScript.Shell",true},
  {"Workbook_Open\x00powershell",true},
  {"Ordinary formatting Macro, no autorun or shell",false},
  {"AutoOpen\x00MSGBOX Hello",false},
  {"WScript.Shell\x00normal macro text",false},
 }{
  p:=v42OfficeZip(t,[]byte(tc.code))
  score:=0;why:=[]string{}
  inspectV42MacroPackage(p,strings.ToLower(filepath.Ext(p)),&score,&why)
  if (score>=40)!=tc.want{t.Fatalf("macro %q score=%d reasons=%v",tc.code,score,why)}
 }
}
