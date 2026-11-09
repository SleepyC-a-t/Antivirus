package main

import (
 "context"
 "bytes"
 "encoding/binary"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "testing"
)

// An inert, NON-RUNNABLE synthetic PE with conventional .text/.idata sections.
// Its real import table names VirtualAllocEx, WriteProcessMemory and
// CreateRemoteThread. It has no entrypoint code and is NEVER executed.
func makeInertTripleImportPE() []byte {
 b:=make([]byte,0x1800)
 put16:=func(o int,v uint16){binary.LittleEndian.PutUint16(b[o:o+2],v)}
 put32:=func(o int,v uint32){binary.LittleEndian.PutUint32(b[o:o+4],v)}
 put64:=func(o int,v uint64){binary.LittleEndian.PutUint64(b[o:o+8],v)}
 copy(b,[]byte("MZ"));put32(0x3c,0x80);copy(b[0x80:],[]byte{'P','E',0,0})
 h:=0x84;put16(h,0x8664);put16(h+2,2);put16(h+16,0xf0);put16(h+18,0x22)
 opt:=0x98;put16(opt,0x20b);put32(opt+4,0x1000);put32(opt+8,0x400)
 put32(opt+16,0x1000);put32(opt+20,0x1000);put64(opt+24,0x140000000)
 put32(opt+32,0x1000);put32(opt+36,0x200);put32(opt+56,0x3000)
 put32(opt+60,0x400);put16(opt+68,3);put32(opt+108,16)
 put32(opt+120,0x2000);put32(opt+124,0x100)
 s:=opt+0xf0;copy(b[s:],".text");put32(s+8,0x1000);put32(s+12,0x1000)
 put32(s+16,0x1000);put32(s+20,0x400);put32(s+36,0x60000020)
 s+=40;copy(b[s:],".idata");put32(s+8,0x400);put32(s+12,0x2000)
 put32(s+16,0x400);put32(s+20,0x1400);put32(s+36,0x40000040)
 put32(0x1400,0x2050);put32(0x140c,0x2090);put32(0x1410,0x2050)
 for i,rva:=range []uint64{0x20b0,0x20d0,0x20f0}{put64(0x1450+i*8,rva)}
 copy(b[0x1490:],"kernel32.dll\x00")
 copy(b[0x14b2:],"VirtualAllocEx\x00")
 copy(b[0x14d2:],"WriteProcessMemory\x00")
 copy(b[0x14f2:],"CreateRemoteThread\x00")
 return b
}

func TestSecurityRealScanPipelineReachesTripleImportSignatureHook(t *testing.T){
 dir:=t.TempDir()
 pe:=filepath.Join(dir,"inert-triple-import.exe")
 if err:=os.WriteFile(pe,makeInertTripleImportPE(),0600);err!=nil{t.Fatal(err)}
 corroborated:=filepath.Join(dir,"inert-triple-with-overlay.exe")
 overlay:=append(makeInertTripleImportPE(),bytes.Repeat([]byte{0},512*1024)...)
 if err:=os.WriteFile(corroborated,overlay,0600);err!=nil{t.Fatal(err)}
 control:=filepath.Join(dir,"benign-document.txt")
 if err:=os.WriteFile(control,[]byte("ordinary document"),0600);err!=nil{t.Fatal(err)}
 // Override only the full-scan drive enumerator; the real full-scan
 // worker, file traversal, PE inspection and trust hook remain unchanged.
 savedRoots:=fullScanDriveRoots
 fullScanDriveRoots=func()[]string{return []string{dir}}
 defer func(){fullScanDriveRoots=savedRoots}()
 saved:=verifyPESignature
 var calls atomic.Int64
 verifyPESignature=func(path string)(string,string){
    calls.Add(1)
    if path!=pe&&path!=corroborated {t.Errorf("unexpected signature path %q",path)}
    return "Not verified (synthetic fixture)", "Unverified"
 }
 defer func(){verifyPESignature=saved}()
 app:=newApp(nil)
 ctx,err:=app.begin("heuristic:full");if err!=nil{t.Fatal(err)}
 err=app.runHeuristic(ctx,"full","")
 app.finish(err)
 if err!=nil{t.Fatal(err)}
 st,findings:=app.snapshot()
 if st.Files!=3{t.Fatalf("scan worker skipped or executed a sample: %+v",st)}
 if calls.Load()!=2{t.Fatalf("real file walker and PE analyzer must call native trust for both import sets: %d",calls.Load())}
 if len(findings)==0{t.Fatal("expected static PE indicators not reported")}
 foundCorroborated:=false
 foundAdvisory:=false
 for _,f:=range findings {
   joined:=strings.Join(f.Reasons," | ")
   if strings.EqualFold(f.Path,pe) {
     // The temp-directory location can independently contribute to a total
     // review score. Do not mistake that for a >=40 score from the PE imports.
     // Check the actual PE reason instead of the file's combined score.
     foundAdvisory=strings.Contains(joined,"PE import triad is advisory")
     if strings.Contains(joined,"Substantial PE overlay alongside remote-memory APIs"){
       t.Errorf("uncorroborated PE incorrectly received overlay corroboration: %+v",f)
     }
   }
   if strings.EqualFold(f.Path,corroborated)&&f.Score>=40&&
      strings.Contains(joined,"Substantial PE overlay alongside remote-memory APIs"){
     foundCorroborated=true
   }
 }
 if !foundAdvisory{t.Fatalf("ordinary triple-import PE did not retain advisory context: %+v",findings)}
 if !foundCorroborated{t.Fatalf("corroborated PE overlay not identified by actual scan: %+v",findings)}
 // Zero launches are performed in the injectable hook; actual child-process
 // absence must be verified independently by Windows ETW, not asserted here.
}

func TestSecurityPEImportCorroborationPolicy(t *testing.T) {
 cases:=[]struct{name string;names map[string]bool; entropy,packed,overlay bool;positive bool}{
  {"triple import",map[string]bool{"virtualallocex":true,"writeprocessmemory":true,"createremotethread":true},false,false,false,false},
  {"triple plus packed",map[string]bool{"ntallocatevirtualmemory":true,"ntwritevirtualmemory":true,"ntcreatethreadex":true},true,true,true,true},
  {"debugger reads memory",map[string]bool{"virtualallocex":true,"readprocessmemory":true,"createremotethread":true},true,false,false,false},
  {"ordinary alloc",map[string]bool{"virtualalloc":true,"virtualprotect":true},true,true,true,false},
  {"only write and allocate",map[string]bool{"virtualallocex":true,"writeprocessmemory":true},true,true,true,false},
 }
 for _,tc:=range cases {
  score,_:=v42PEIndicators(tc.names,tc.entropy,tc.packed,tc.overlay)
  if (score>=40)!=tc.positive{t.Errorf("%s: score %d, positive %t",tc.name,score,tc.positive)}
 }
}

var _=context.Background
