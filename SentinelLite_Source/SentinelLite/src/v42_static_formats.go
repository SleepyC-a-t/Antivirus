package main

import (
 "archive/zip"
 "debug/pe"
 "io"
 "math"
 "os"
 "path/filepath"
 "regexp"
 "strings"
)

const peDeepScanMaxBytes int64 = 48*1024*1024

func peSampleEntropy(b []byte)float64 {
 if len(b)==0{return 0}
 var bins [256]int
 for _,v:=range b{bins[v]++}
 h:=0.0
 for _,n:=range bins {
   if n==0{continue}
   p:=float64(n)/float64(len(b))
   h-=p*math.Log2(p)
 }
 return h
}
func peSuspiciousImportCombination(names []string)bool{
 alloc,write,thread:=false,false,false
 for _,name:=range names{
  l:=strings.ToLower(name)
  alloc=alloc||strings.Contains(l,"virtualallocex")||strings.Contains(l,"ntallocatevirtualmemory")
  write=write||strings.Contains(l,"writeprocessmemory")||strings.Contains(l,"ntwritevirtualmemory")
  thread=thread||strings.Contains(l,"createremotethread")||strings.Contains(l,"ntcreatethreadex")||strings.Contains(l,"queueuserapc")
 }
 return alloc&&write&&thread
}
func inspectPEInternals(path string,info os.FileInfo,score *int,reasons *[]string){
 if info.Size()<512||info.Size()>peDeepScanMaxBytes{return}
 ext:=strings.ToLower(filepath.Ext(path))
 switch ext{case ".exe",".dll",".scr",".sys",".cpl":default:return}
 f,err:=pe.Open(path)
 if err!=nil{return} // malformed PE is not proof of malware
 defer f.Close()
 if len(f.Sections)>48{return}
 packed:=0
 for _,section:=range f.Sections{
   n:=strings.ToLower(strings.TrimRight(section.Name,"\x00"))
   if n==".upx0"||n==".upx1"||n==".aspack"||n==".mpress" {packed++}
   // Bounded sample, no full section expansion or code execution.
   data,_:=io.ReadAll(io.LimitReader(section.Open(),64*1024))
   if len(data)>=8192&&peSampleEntropy(data)>7.85 {packed++}
 }
 imports,err:=f.ImportedSymbols()
 if err==nil&&peSuspiciousImportCombination(imports){
   *score+=45
   *reasons=append(*reasons,"PE import combination: remote process allocation, write and thread creation (can be used by legitimate debuggers)")
   if packed>=2{
      *score+=18
      *reasons=append(*reasons,"PE imports combined with packed/high-entropy sections (corroborating signal)")
   }
 }
 // High entropy alone, unsupported imports, or an unsigned executable are
 // *not* flagged. They frequently appear in legitimate software.
}
var pdfOpenJS=regexp.MustCompile(`(?s)/OpenAction\s+\d+\s+\d+\s+R`)
var pdfScriptAction=regexp.MustCompile(`(?s)/S\s*/JavaScript\b`)
var pdfLaunchAction=regexp.MustCompile(`(?s)/S\s*/Launch\b`)
func inspectPDFStructure(buf []byte,score *int,reasons *[]string){
 if len(buf)<16||!strings.HasPrefix(string(buf[:8]),"%PDF-"){return}
 if pdfOpenJS.Match(buf)&&pdfScriptAction.Match(buf){
   *score+=60
   *reasons=append(*reasons,"PDF has an automatic document-open action and JavaScript action (structural indicator, may be benign)")
 }
 if pdfLaunchAction.Match(buf){
   *score+=52
   *reasons=append(*reasons,"PDF defines an external launch action; review requested file or command")
 }
}
func inspectOOXMLMacroEntries(files []*zip.File,score *int,reasons *[]string){
 macro:=false
 autorun:=false
 for _,file:=range files{
   if file.UncompressedSize64>512*1024||file.CompressedSize64>512*1024{continue}
   if strings.EqualFold(filepath.Base(file.Name),"vbaProject.bin"){
      macro=true
      rc,err:=file.Open();if err!=nil{continue}
      b,_:=io.ReadAll(io.LimitReader(rc,128*1024));_ = rc.Close()
      low:=strings.ToLower(string(b))
      autorun=strings.Contains(low,"autoopen")||strings.Contains(low,"document_open")||strings.Contains(low,"workbook_open")
   }
 }
 // A macro-enabled document by itself is not suspicious. This is a bounded
 // visible-string heuristic, not a full OLE/VBA parser.
 if macro&&autorun{
    *score+=45
    *reasons=append(*reasons,"Office document includes VBA project with visible auto-run names (macro not executed)")
 }
}
