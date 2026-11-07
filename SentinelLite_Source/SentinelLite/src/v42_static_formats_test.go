package main
import(
 "archive/zip"
 "bytes"
 "strings"
 "testing"
)
func TestV42PEInternalsCorrelatedSignals(t *testing.T){
 if !peSuspiciousImportCombination([]string{"KERNEL32.dll:VirtualAllocEx","KERNEL32.dll:WriteProcessMemory","KERNEL32.dll:CreateRemoteThread"}) {t.Fatal("three-stage remote process import pattern missed")}
 if peSuspiciousImportCombination([]string{"KERNEL32.dll:VirtualAllocEx","KERNEL32.dll:WriteProcessMemory"}) {t.Fatal("debugger-style imports without thread creation flagged")}
 if peSuspiciousImportCombination([]string{"KERNEL32.dll:CreateRemoteThread"}) {t.Fatal("single legitimate import flagged")}
 if got:=peSampleEntropy(bytes.Repeat([]byte{0},16384));got!=0{t.Fatalf("constant data entropy %v",got)}
}
func TestV42PDFActionStructuresAndBenignLookalikes(t *testing.T){
 cases:=[]struct{label string;data []byte;want bool}{
 {"automatic PDF JavaScript",[]byte("%PDF-1.6\n1 0 obj<< /OpenAction 4 0 R >>endobj\n4 0 obj<</S /JavaScript /JS (app.alert(1))>>"),true},
 {"PDF external launch",[]byte("%PDF-1.6\n1 0 obj<</S /Launch /F (example.txt)>>endobj"),true},
 {"manual JavaScript",[]byte("%PDF-1.6\n1 0 obj<</S /JavaScript /JS (app.alert(1))>>"),false},
 {"plain quoted text",[]byte("%PDF-1.6\nThis guide discusses /OpenAction and /JavaScript"),false},
 {"not a PDF",[]byte("This is a document about /S /Launch"),false},
 }
 for _,c:=range cases{
   score:=0;reasons:=[]string{}
   inspectPDFStructure(c.data,&score,&reasons)
   if (score>=40)!=c.want{t.Fatalf("case %s score=%d reasons=%v",c.label,score,reasons)}
 }
}
func TestV42OfficeAutoMacroAndBenign(t *testing.T){
 makeArchive:=func(content string)[]*zip.File{
   var data bytes.Buffer
   writer:=zip.NewWriter(&data)
   f,_:=writer.Create("word/vbaProject.bin")
   _,_=f.Write([]byte(content));_=writer.Close()
   reader,err:=zip.NewReader(bytes.NewReader(data.Bytes()),int64(data.Len()))
   if err!=nil{t.Fatal(err)}
   return reader.File
 }
 for _,tc:=range []struct{script string;flag bool}{
    {"VBA AutoOpen\x00Private Sub Document_Open()",true},
    {"Ordinary project macros Sub FormatCell()",false},
 }{
   score:=0;reasons:=[]string{}
   inspectOOXMLMacroEntries(makeArchive(tc.script),&score,&reasons)
   if (score>=40)!=tc.flag{t.Fatalf("macro %s score=%d",strings.TrimSpace(tc.script),score)}
 }
}
