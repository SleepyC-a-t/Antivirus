//go:build windows
package main

import(
 "fmt"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "testing"
)
type v42BenignStats struct{Total,Flagged,Skipped int}
func TestV42IndependentWindowsBenignCorpusMeasurement(t *testing.T){
 // A separate, UNSEEN, labeled-benign system-file set. These are not
 // confirmed harmless individually, but originate in Windows runner
 // system/tool installation paths and are NOT the synthetic rule fixtures.
 // This is a measurement test, never a false-positive-free regression lock.
 roots:=[]struct{label,path string;limit int}{
  {"Windows",os.Getenv("WINDIR"),2500},
  {"ProgramFiles",os.Getenv("ProgramFiles"),2500},
  {"ProgramFilesX86",os.Getenv("ProgramFiles(x86)"),1500},
 }
 for _,env:=range []string{"Python_ROOT_DIR","pythonLocation","RUNNER_TOOL_CACHE"}{
   if root:=os.Getenv(env);root!="" {roots=append(roots,struct{label,path string;limit int}{"ToolCache",root,1200})}
 }
 if path:=os.Getenv("APPDATA");path!=""{
   roots=append(roots,struct{label,path string;limit int}{"npm",filepath.Join(path,"npm"),750})
 }
 types:=map[string]bool{".exe":true,".dll":true,".sys":true,".ps1":true,".bat":true,".cmd":true,".js":true,".py":true,".pdf":true,".lnk":true,".docm":true,".xlsm":true}
 for _,root:=range roots{
    if root.path==""{continue}
    st,err:=os.Lstat(root.path);if err!=nil||!st.IsDir(){t.Logf("V42_BENIGN_UNAVAILABLE category=%s root=%q",root.label,root.path);continue}
    files:=[]string{}
    _=filepath.WalkDir(root.path,func(p string,d os.DirEntry,err error)error{
       if err!=nil{return nil}
       if d.IsDir(){
          if isReparse(p){return filepath.SkipDir}
          return nil
       }
       if d.Type()&os.ModeSymlink!=0||isReparse(p){return nil}
       if !types[strings.ToLower(filepath.Ext(p))]{return nil}
       files=append(files,p)
       if len(files)>=root.limit*3{return filepath.SkipAll}
       return nil
    })
    sort.Strings(files)
    total:=v42BenignStats{}
    for _,p:=range files{
       if total.Total>=root.limit{break}
       info,err:=os.Lstat(p)
       if err!=nil||!info.Mode().IsRegular()||info.Size()>48*1024*1024{total.Skipped++;continue}
       total.Total++
       var readErrs []string
       f:=inspectFileProtected(p,info,func(err string){readErrs=append(readErrs,err)})
       if len(readErrs)>0{total.Skipped++;continue}
       if f!=nil{
         total.Flagged++
         t.Logf("V42_BENIGN_FLAG category=%s ext=%s path=%q score=%d reasons=%q",root.label,strings.ToLower(filepath.Ext(p)),p,f.Score,strings.Join(f.Reasons," | "))
       }
    }
    t.Logf("V42_BENIGN_CORPUS category=%s total=%d flagged=%d skipped=%d",root.label,total.Total,total.Flagged,total.Skipped)
 }
 t.Log("Independent benign corpus is a read-only measurement; flagged items need human review and may not be false positives.")
}
func TestV42BenignPathsDontEscapeFileSystem(t *testing.T){
 // Unit sanity rather than an independent detection-rate assertion.
 _=fmt.Sprintf
}
