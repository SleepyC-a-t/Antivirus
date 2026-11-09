package main

import (
 "archive/zip"
 "bytes"
 "debug/pe"
 "encoding/binary"
 "fmt"
 "io"
 "math"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "unicode/utf16"
)

// v4.2 structured inspection is bounded and strictly static.
// No scanned file, macro, shortcut target or PDF action is executed.
func v42SectionEntropy(buf []byte)float64{
 if len(buf)==0{return 0}
 var counts [256]int
 for _,b:=range buf{counts[b]++}
 total:=float64(len(buf))
 entropy:=0.0
 for _,c:=range counts{
  if c!=0{p:=float64(c)/total;entropy-=p*math.Log2(p)}
 }
 return entropy
}
// Injectable in tests: exercising the whole file -> PE analyzer path must
// reach the native signature check, without starting a command interpreter.
var verifyPESignature = v42VerifySignature

func inspectV42PE(p string,st os.FileInfo,score *int,reasons *[]string){
 ext:=strings.ToLower(filepath.Ext(p))
 switch ext{case ".exe",".dll",".sys",".scr",".cpl":default:return}
 if st.Size()<512||st.Size()>64*1024*1024{return}
 image,err:=pe.Open(p);if err!=nil{return}
 defer image.Close()
 if len(image.Sections)==0||len(image.Sections)>96{return}
 var highEntropy bool
 var packedSection bool
 end:=int64(0)
 for _,sec:=range image.Sections{
  secEnd:=int64(sec.Offset)+int64(sec.Size)
  if secEnd>end{end=secEnd}
  if sec.Characteristics&0x20000000==0{continue} // executable
  reader:=sec.Open()
  sample,err:=io.ReadAll(io.LimitReader(reader,32*1024))
  if err!=nil||len(sample)<4096{continue}
  if v42SectionEntropy(sample)>=7.55{
   highEntropy=true
   n:=strings.ToLower(strings.Trim(sec.Name,"\x00"))
   if strings.HasPrefix(n,"upx")||strings.Contains(n,"vmp")||strings.Contains(n,"aspack"){packedSection=true}
  }
 }
 imports,err:=image.ImportedSymbols()
 if err!=nil{return}
 imported:=map[string]bool{}
 for _,sym:=range imports{
   name:=strings.ToLower(strings.SplitN(sym,":",2)[0])
   imported[name]=true
 }
 addition,indicators:=v42PEIndicators(imported,highEntropy,packedSection,
    end>0&&st.Size()>end+256*1024&&st.Size()-end>st.Size()/4)
 if addition==0{return}
 *reasons=append(*reasons,indicators...)
 // A trusted Windows Authenticode signature is exculpatory context, not
 // proof of safety. Avoid expensive trust verification for every PE.
 if sig,_:=verifyPESignature(p);strings.HasPrefix(sig,"Trusted"){
   addition-=20
   *reasons=append(*reasons,"Trusted Authenticode signature reduces the PE heuristic score (not a guarantee of safety)")
 }
 if addition>0{*score+=addition}
}
// v42PEIndicators separates conservative policy from parsing, so both
// suspicious import combinations and benign lookalikes can be tested
// without embedding a real malware executable.
func v42PEIndicators(imported map[string]bool,highEntropy,packed,overlay bool)(int,[]string){
 alloc:=imported["virtualallocex"]||imported["ntallocatevirtualmemory"]
 remote:=imported["createremotethread"]||imported["ntcreatethreadex"]||imported["queueuserapc"]
 write:=imported["writeprocessmemory"]||imported["ntwritevirtualmemory"]
 if !alloc||!remote||!write{return 0,nil}
 // Import triples are common in legitimate debugger/virtualization/browser tools.
 // Independent benign CI survey found 31 matches / 8,499 parsed PEs.
 // Uncorroborated imports MUST remain advisory (<40), not a standalone alert.
 addition:=28
 why:=[]string{"PE import triad is advisory until corroborated by entropy, overlay or other suspicious evidence (also used by legitimate debugging software)"}
 if highEntropy {
    addition+=12
    why=append(why,"High-entropy PE executable section alongside remote-memory APIs")
 }
 if overlay{
    addition+=12
    why=append(why,"Substantial PE overlay alongside remote-memory APIs")
 }
 if packed&&highEntropy{
    addition+=12
    why=append(why,"Packer-like executable section name alongside suspicious imports")
 }
 return addition,why
}
// Operate only on PDF dictionary syntax outside comments and literal strings.
// This is bounded lexical inspection, not a full PDF parser or stream decoder.
var pdfDictOpenAction = regexp.MustCompile(`(?i)/OpenAction(?:\s|/|>|$)`)
var pdfDictJavaScript = regexp.MustCompile(`(?i)/S\s*/JavaScript(?:\s|/|>|$)`)
var pdfDictJSKey = regexp.MustCompile(`(?i)/JS(?:\s|/|>|$)`)
var pdfDictLaunch = regexp.MustCompile(`(?i)/S\s*/Launch(?:\s|/|>|$)`)
var pdfDictFileKey = regexp.MustCompile(`(?i)/F(?:\s|\(|/|<|$)`)
var pdfDictFileTarget = regexp.MustCompile(`(?i)^/F\s*(?:\((?:[^\\)]|\\.){1,256}\.(?:exe|cmd|ps1)\)|/[^\s<>\[\]()]{1,256}\.(?:exe|cmd|ps1))`)

type pdfActionDict struct{ raw,syntax []byte }

// pdfMaskCommentAndStringBytes preserves offsets while neutralizing apparent
// PDF operators inside titles, literal strings, hex data and comments.
func pdfMaskCommentAndStringBytes(buf []byte) []byte {
 out:=append([]byte(nil),buf...)
 comment:=false
 literalDepth:=0
 hexString:=false
 escaped:=false
 for i,c:=range buf{
  if comment{
   out[i]=' '
   if c=='\r'||c=='\n'{comment=false}
   continue
  }
  if literalDepth>0{
   out[i]=' '
   if escaped{escaped=false;continue}
   if c=='\\'{escaped=true;continue}
   if c=='(' {literalDepth++}
   if c==')' {literalDepth--}
   continue
  }
  if hexString{
   out[i]=' '
   if c=='>'{hexString=false}
   continue
  }
  if c=='%' {comment=true;out[i]=' ';continue}
  if c=='(' {literalDepth=1;out[i]=' ';continue}
  if c=='<' && (i+1>=len(buf)||buf[i+1]!='<') {
   // The first '<' of a dictionary and its matching '>' remain visible;
   // the inside of a PDF hex string is not actionable PDF syntax.
   if i==0||buf[i-1]!='<'{hexString=true;out[i]=' '}
  }
 }
 return out
}

func pdfActionDictionaries(buf []byte) []pdfActionDict{
 const maxDictBytes=8192
 syntax:=pdfMaskCommentAndStringBytes(buf)
 dicts:=make([]pdfActionDict,0,8)
 starts:=make([]int,0,4)
 for i:=0;i+1<len(syntax);i++{
  if syntax[i]=='<'&&syntax[i+1]=='<'{
   if len(starts)<8{starts=append(starts,i)}
   i++
   continue
  }
  if syntax[i]=='>'&&syntax[i+1]=='>'{
   if n:=len(starts);n>0{
    start:=starts[n-1]
    starts=starts[:n-1]
    if i+2-start<=maxDictBytes {
     dicts=append(dicts,pdfActionDict{raw:buf[start:i+2],syntax:syntax[start:i+2]})
    }
   }
   i++
  }
 }
 return dicts
}
func inspectV42PDF(buf []byte,score *int,reasons *[]string){
 if len(buf)<16||!bytes.HasPrefix(buf,[]byte("%PDF-")){return}
 dicts:=pdfActionDictionaries(buf)
 hasOpenAction:=false
 hasJavaScriptAction:=false
 hasExecutableLaunch:=false
 for _,d:=range dicts{
  if pdfDictOpenAction.Match(d.syntax){hasOpenAction=true}
  if pdfDictJavaScript.Match(d.syntax)&&pdfDictJSKey.Match(d.syntax){
   hasJavaScriptAction=true
  }
  if pdfDictLaunch.Match(d.syntax){
   // /F must itself be real dictionary syntax. Only then examine the
   // immediately following raw file-spec string for an executable suffix.
   for _,loc:=range pdfDictFileKey.FindAllIndex(d.syntax,12){
    if pdfDictFileTarget.Match(d.raw[loc[0]:]){
     hasExecutableLaunch=true
     break
    }
   }
  }
 }
 if hasOpenAction&&hasJavaScriptAction{
  *score+=52
  *reasons=append(*reasons,"PDF has document-open and JavaScript action dictionaries (limited structural inspection, not proof of exploit)")
 }
 if hasExecutableLaunch{
  *score+=51
  *reasons=append(*reasons,"PDF has a launch-action dictionary referencing an executable or script")
 }
}
func v42LNKString(buf []byte,pos *int,unicode bool)(string,error){
 if *pos+2>len(buf){return "",fmt.Errorf("truncated Shell Link StringData")}
 n:=int(binary.LittleEndian.Uint16(buf[*pos:*pos+2]));*pos+=2
 width:=1;if unicode{width=2}
 if n>32768||n>len(buf)/width||*pos>len(buf)-n*width{return "",fmt.Errorf("invalid Shell Link StringData length")}
 data:=buf[*pos:*pos+n*width];*pos+=n*width
 if !unicode{return string(data),nil}
 chars:=make([]uint16,n)
 for i:=range chars{chars[i]=binary.LittleEndian.Uint16(data[i*2:i*2+2])}
 return string(utf16.Decode(chars)),nil
}
func inspectV42LNK(buf []byte,score *int,reasons *[]string){
 if len(buf)<76||binary.LittleEndian.Uint32(buf[:4])!=76{return}
 clsid:=[]byte{0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}
 if !bytes.Equal(buf[4:20],clsid){return}
 flags:=binary.LittleEndian.Uint32(buf[20:24])
 show:=binary.LittleEndian.Uint32(buf[60:64])
 pos:=76
 if flags&0x1!=0{
  if pos+2>len(buf){return}
  count:=int(binary.LittleEndian.Uint16(buf[pos:pos+2]))
  if pos+2+count>len(buf){return}
  pos+=2+count
 }
 if flags&0x2!=0{
  if pos+4>len(buf){return}
  count:=int(binary.LittleEndian.Uint32(buf[pos:pos+4]))
  if count<0x1c||count>len(buf)-pos{return}
  pos+=count
 }
 unicode:=flags&0x80!=0
 var relPath,args string
 for _,slot:=range []struct{mask uint32;kind string}{
  {0x4,"name"},{0x8,"relative"},{0x10,"working"},{0x20,"args"},{0x40,"icon"},
 }{
  if flags&slot.mask==0{continue}
  value,err:=v42LNKString(buf,&pos,unicode)
  if err!=nil{return}
  if slot.kind=="relative"{relPath=value}
  if slot.kind=="args"{args=value}
 }
 if args==""{return}
 text:=strings.ToLower(relPath+" "+args)
 shell:=strings.Contains(text,"powershell")||strings.Contains(text,"pwsh.exe")||strings.Contains(text,"cmd.exe")||strings.Contains(text,"mshta")
 encoded:=strings.Contains(text,"-encodedcommand")||strings.Contains(text," -enc ")||strings.Contains(text,"-enc:")||strings.Contains(text,"-e ")
 remote:=strings.Contains(text,"http://")||strings.Contains(text,"https://")
 if shell&&(encoded||(remote&&show==7)){
  *score+=78
  *reasons=append(*reasons,"Parsed Shell Link invokes a command interpreter with encoded arguments or hidden network retrieval")
 }
}
func inspectV42MacroPackage(path,ext string,score *int,reasons *[]string){
 if ext!=".docm"&&ext!=".xlsm"&&ext!=".pptm"{return}
 zr,err:=zip.OpenReader(path);if err!=nil{return}
 defer zr.Close()
 if len(zr.File)>4096{return}
 for _,entry:=range zr.File{
  if !strings.EqualFold(filepath.Base(entry.Name),"vbaProject.bin"){continue}
  if entry.UncompressedSize64>2*1024*1024||entry.CompressedSize64>2*1024*1024{continue}
  rc,err:=entry.Open();if err!=nil{continue}
  payload,err:=io.ReadAll(io.LimitReader(rc,128*1024));_ = rc.Close()
  if err!=nil{continue}
  low:=strings.ToLower(string(payload))
  autorun:=strings.Contains(low,"autoopen")||strings.Contains(low,"document_open")||strings.Contains(low,"workbook_open")||strings.Contains(low,"autoclose")
  risky:=strings.Contains(low,"powershell")||strings.Contains(low,"wscript.shell")||strings.Contains(low,"downloadstring")||strings.Contains(low,"shell(")
  if autorun&&risky{
    *score+=51
    *reasons=append(*reasons,"Macro-enabled OOXML package contains auto-run and command-execution strings (not proof of execution)")
  }
  // The presence of a legitimate macro alone is not malicious.
  return
 }
}
