package main

import (
 "archive/zip"
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/binary"
 "io"
 "path/filepath"
 "regexp"
 "strings"
 "unicode/utf16"
)

// Confirm NT signature, not just the MZ prefix.
func isPEHeader(b []byte) bool {
 if len(b)<68 || b[0]!='M' || b[1]!='Z' {return false}
 off:=binary.LittleEndian.Uint32(b[0x3c:0x40])
 return off>=0x40 && uint64(off)+4<=uint64(len(b)) && bytes.Equal(b[off:off+4],[]byte{'P','E',0,0})
}
func isDocumentOrImage(ext string) bool {
 switch ext {case ".jpg",".jpeg",".png",".gif",".webp",".pdf",".txt": return true}
 return false
}
func isZIPContainer(ext string) bool {
 switch ext {case ".zip",".jar",".docx",".xlsx",".pptx",".docm",".xlsm",".pptm":return true}
 return false
}
func decodeScriptText(b []byte) string {
 if len(b)<2 {return string(b)}
 little:=true
 payload:=b
 if b[0]==0xff && b[1]==0xfe {payload=b[2:]} else if b[0]==0xfe && b[1]==0xff {little=false;payload=b[2:]} else {
  if len(b)<24 {return string(b)}
  pairs:=len(b)/2
  if pairs>128 {pairs=128}
  le,be:=0,0
  for i:=0;i<pairs*2;i+=2 {
   if b[i+1]==0 && b[i]>=0x20 && b[i]<=0x7e {le++}
   if b[i]==0 && b[i+1]>=0x20 && b[i+1]<=0x7e {be++}
  }
  if le*100>=pairs*70 {little=true} else if be*100>=pairs*70 {little=false} else {return string(b)}
 }
 words:=make([]uint16,0,len(payload)/2)
 for i:=0;i+1<len(payload);i+=2 {
  if little {words=append(words,binary.LittleEndian.Uint16(payload[i:i+2]))} else {words=append(words,binary.BigEndian.Uint16(payload[i:i+2]))}
 }
 return string(utf16.Decode(words))
}
func hasMisleadingBidiControls(name string) bool {
 return strings.ContainsAny(name,"\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
}
// No archive entry is executed or extracted to disk; bound both depth and reads.
func inspectZIP(p string,score *int,reasons *[]string) {
 _=inspectZIPWithError(p,score,reasons)
}
func inspectZIPWithError(p string,score *int,reasons *[]string) error {
 zr,err:=zip.OpenReader(p);if err!=nil{return err};defer zr.Close()
 budget:=int64(2*1024*1024)
 inspected:=0
 inspectArchiveEntriesLimited(zr.File,0,&budget,&inspected,score,reasons)
 return nil
}
func inspectArchiveEntries(files []*zip.File,depth int,budget *int64,score *int,reasons *[]string) bool {
    inspected:=0
    return inspectArchiveEntriesLimited(files,depth,budget,&inspected,score,reasons)
}
func inspectArchiveEntriesLimited(files []*zip.File,depth int,budget *int64,inspected *int,score *int,reasons *[]string) bool {
 const maxEntries=4096
 const maxEntryBytes=int64(128*1024)
 const maxNestedBytes=int64(512*1024)
 for _,file:=range files {
  if *inspected>=maxEntries || *budget<=0 {break}
  *inspected++
  if file.FileInfo().IsDir(){continue}
  name:=truncate(file.Name,120)
  ext:=strings.ToLower(filepath.Ext(file.Name))
  if doubleExt.MatchString(filepath.Base(file.Name)){
   *score+=65;*reasons=append(*reasons,"Archive contains disguised executable: "+name);return true
  }
  nested:=depth<3 && isZIPContainer(ext)
  // The harmless EICAR test signature may be inside *any* archive
  // entry, including eicar.com. Do not restrict detection by extension.
  exactEICARCandidate:=file.UncompressedSize64>=68&&file.UncompressedSize64<=128
  if !nested && !exactEICARCandidate && !scriptExtensions[ext] && !isThreatScriptExtension(ext) && ext!=".lnk" && !isDocumentOrImage(ext) && !stage9InspectableExtension(ext) && !stage10InspectableExtension(ext) && !stage11InspectableExtension(ext) && !stage12InspectableExtension(ext){continue}
  // Reject decompression bombs: cap entry size, compressed bytes,
  // expansion ratio, recursion depth and a global archive read budget.
  if file.CompressedSize64>16*1024*1024 {continue}
  if file.UncompressedSize64 > 0 && file.UncompressedSize64>file.CompressedSize64*100+4096 {continue}
  limit:=maxEntryBytes
  if nested {limit=maxNestedBytes}
  if limit>*budget {limit=*budget}
  rc,err:=file.Open();if err!=nil{continue}
  buf,readErr:=io.ReadAll(io.LimitReader(rc,limit));_ = rc.Close()
  *budget-=int64(len(buf));if readErr!=nil{continue}
  if nested {
   if int64(len(buf))!=int64(file.UncompressedSize64){continue}
   z,err:=zip.NewReader(bytes.NewReader(buf),int64(len(buf)))
   if err==nil && inspectArchiveEntriesLimited(z.File,depth+1,budget,inspected,score,reasons){return true}
   continue
  }
  if file.UncompressedSize64==uint64(len(buf)) && isExactEICAR(buf){
   *score+=110;*reasons=append(*reasons,"Archive contains exact harmless EICAR test file: "+name);return true
  }
  if isDocumentOrImage(ext)&&isPEHeader(buf){
   *score+=80;*reasons=append(*reasons,"Archive document/image contains PE header: "+name);return true
  }
  if scriptExtensions[ext] || ext==".lnk"{
   partialScore:=0;partialReasons:=[]string{}
   if scriptExtensions[ext] {inspectScript(buf,&partialScore,&partialReasons)} else {inspectShortcut(buf,&partialScore,&partialReasons)}
   if partialScore>=40 {
    *score+=partialScore
    for _,r:=range partialReasons{*reasons=append(*reasons,"Archive entry "+name+": "+r)}
    return true
   }
  }
  // Inspect additional high-confidence patterns in fully read archive entries.
  // Do not turn a truncated JSON/XML/script sample into a misleading verdict.
  // The archive budget and nesting limits above apply to all these checks.
  if file.UncompressedSize64==uint64(len(buf)) {
   entryScore:=0
   entryReasons:=[]string{}
   if stage9InspectableExtension(ext) || isThreatScriptExtension(ext) || isDocumentOrImage(ext) {
    inspectStage9Content(filepath.Base(file.Name),ext,buf,&entryScore,&entryReasons)
   }
   if stage10InspectableExtension(ext) {
    inspectStage10Content(filepath.Base(file.Name),ext,buf,&entryScore,&entryReasons)
   }
   if isThreatScriptExtension(ext) {
    inspectThreatBehavior(buf,ext,&entryScore,&entryReasons)
   }
   if stage11InspectableExtension(ext) || isThreatScriptExtension(ext) || ext==".html" || ext==".htm" {
    inspectStage11Content(filepath.Base(file.Name),ext,buf,&entryScore,&entryReasons)
   }
   if stage12InspectableExtension(ext) || isThreatScriptExtension(ext) {
    inspectStage12Content(filepath.Base(file.Name),ext,buf,&entryScore,&entryReasons)
   }
   if entryScore>=40 {
    *score+=entryScore
    for _,reason:=range entryReasons {
     *reasons=append(*reasons,"Archive entry "+name+": "+reason)
    }
    return true
   }
  }
 }
 return false
}


// Only match an EICAR test file, not a document that quotes the test string.
// EICAR is a 68-byte standardized harmless test file. Check its digest
// instead of embedding the full detector-triggering test signature inside
// the shipped EXE. The complete signature is never stored in release data.
const eicarTestLength = 68
const eicarTestSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

func isExactEICAR(buf []byte) bool {
 if len(buf)<eicarTestLength || len(buf)>128 {return false}
 digest:=sha256.Sum256(buf[:eicarTestLength])
 if hex.EncodeToString(digest[:])!=eicarTestSHA256 {return false}
 for _,b:=range buf[eicarTestLength:]{
  switch b {case ' ', '\t', '\n', '\r', 0x1a: default:return false}
 }
 return true
}

func stripLineComments(source string) string {
 var result strings.Builder
 result.Grow(len(source))
 for len(source)>0 {
  idx:=strings.IndexByte(source,'\n')
  if idx<0 {idx=len(source)}
  line:=source[:idx]
  trimmed:=strings.TrimSpace(line)
  comment:=strings.HasPrefix(trimmed,"#")||strings.HasPrefix(trimmed,"//")||strings.HasPrefix(trimmed,"::")
  if len(trimmed)>=4 {comment=comment||strings.EqualFold(trimmed[:4],"rem ")}
  if len(trimmed)>=5 {comment=comment||strings.EqualFold(trimmed[:5],"@rem ")}
  if !comment {result.WriteString(line);result.WriteByte('\n')}
  if idx==len(source){break}
  source=source[idx+1:]
 }
 return result.String()
}

var shortcutEncoded = regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\s+[^\r\n]{0,100}-(?:encodedcommand|enc|en|e)\s+[a-z0-9+/=]{28,}`)
func inspectShortcut(data []byte, score *int, reasons *[]string) {
 source:=strings.ToLower(string(data))
 if !shortcutEncoded.MatchString(source) && len(data)>4 {
  var utf16Text strings.Builder
  for phase:=0;phase<2;phase++ {
   for i:=phase;i+1<len(data);i+=2 {
    if data[i+1]==0 && data[i]>=32 && data[i]<127 {utf16Text.WriteByte(data[i])} else {utf16Text.WriteByte(' ')}
   }
  }
  source=utf16Text.String()
 }
 if shortcutEncoded.MatchString(source){
  *score+=78;*reasons=append(*reasons,"Shortcut contains a PowerShell encoded command (review target and arguments)")
 }
}
