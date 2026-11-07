//go:build windows

package main

import (
 "debug/pe"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "testing"
)

// Prospective, read-only expected-benign PE survey. Not a representative
// population sample and not a genuine-malware evaluation. Per-root counts
// disclose exactly where a 48-point import combination occurs; game launchers
// are counted only if they are actually installed on the Windows CI runner.
func TestSecurityThirdPartyPEImport48PointRuleSurvey(t *testing.T) {
 pf:=os.Getenv("ProgramFiles")
 pf86:=os.Getenv("ProgramFiles(x86)")
 la:=os.Getenv("LOCALAPPDATA")
 roots:=[]struct{label,path string;max int}{
  {"Program Files",pf,2200},
  {"Program Files x86",pf86,2200},
  {"Visual Studio",filepath.Join(pf,"Microsoft Visual Studio"),2000},
  {"Git",filepath.Join(pf,"Git"),800},
  {"Windows Kits",filepath.Join(pf86,"Windows Kits"),1500},
  {"Steam",filepath.Join(pf86,"Steam"),800},
  {"Epic Games",filepath.Join(pf86,"Epic Games"),800},
  {"GOG Galaxy",filepath.Join(pf86,"GOG Galaxy"),800},
  {"User game launchers",filepath.Join(la,"Programs"),1000},
 }
 all,allFlags:=0,0
 for _,root:=range roots{
  if root.path==""{continue}
  stat,err:=os.Stat(root.path)
  if err!=nil||!stat.IsDir(){
   t.Logf("PE_BENIGN_SURVEY root=%q NOT_AVAILABLE (not scored)",root.label)
   continue
  }
  candidates:=[]string{}
  unreadable:=0
  _=filepath.WalkDir(root.path,func(p string,d os.DirEntry,err error)error{
   if err!=nil{unreadable++;return nil}
   if d.IsDir() {if p!=root.path&&isReparse(p){return filepath.SkipDir};return nil}
   if d.Type()&os.ModeSymlink!=0||isReparse(p){return nil}
   ext:=strings.ToLower(filepath.Ext(p))
   if ext!=".exe"&&ext!=".dll"&&ext!=".sys"&&ext!=".scr"&&ext!=".cpl"{return nil}
   candidates=append(candidates,p)
   if len(candidates)>=root.max{return filepath.SkipAll}
   return nil
  })
  sort.Strings(candidates)
  checked,positive:=0,0
  for _,file:=range candidates{
   st,err:=os.Stat(file)
   if err!=nil||st.Size()>64*1024*1024||!st.Mode().IsRegular(){unreadable++;continue}
   image,err:=pe.Open(file)
   if err!=nil{unreadable++;continue}
   imports,importErr:=image.ImportedSymbols()
   _=image.Close()
   if importErr!=nil{unreadable++;continue}
   checked++
   symbols:=map[string]bool{}
   for _,s:=range imports{symbols[strings.ToLower(strings.SplitN(s,":",2)[0])]=true}
   score,reasons:=v42PEIndicators(symbols,false,false,false)
   if score>0 {
    positive++
    t.Logf("PE_BENIGN_IMPORT_ADVISORY root=%q name=%q score=%d reasons=%q",root.label,filepath.Base(file),score,reasons)
   }
  }
  all+=checked;allFlags+=positive
  t.Logf("PE_BENIGN_SURVEY root=%q peParsed=%d tripleImportAdvisories=%d skippedOrUnreadable=%d",root.label,checked,positive,unreadable)
 }
 t.Logf("PE_BENIGN_SURVEY_TOTAL peParsed=%d tripleImportAdvisories=%d expectedBenignOnly=true samplingNonrandom=true",all,allFlags)
 if all<20{t.Fatal("insufficient Windows benign PE imports tested")}
}
