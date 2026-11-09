//go:build windows
package main

import(
 "fmt"
 "math"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "testing"
 "time"
)

type v42CorpusMeasure struct{
 scanned,flagged,unreadable int
 types map[string][2]int
}
func v42Wilson(success,total int)(float64,float64){
 if total<=0{return 0,1}
 const z=1.959963984540054
 n:=float64(total);p:=float64(success)/n;d:=1+z*z/n
 center:=(p+z*z/(2*n))/d
 spread:=z*math.Sqrt((p*(1-p)+z*z/(4*n))/n)/d
 return math.Max(0,center-spread),math.Min(1,center+spread)
}
func v42MeasureBenignRoot(t *testing.T,label,root string,limit int) v42CorpusMeasure{
 t.Helper()
 out:=v42CorpusMeasure{types:map[string][2]int{}}
 if root==""{t.Logf("BENIGN_CORPUS root=%q SKIPPED no path",label);return out}
 root=filepath.Clean(root)
 if st,err:=os.Stat(root);err!=nil||!st.IsDir(){
  t.Logf("BENIGN_CORPUS root=%q SKIPPED unavailable=%q",label,root);return out
 }
 var paths []string
 deadline:=time.Now().Add(4*time.Minute)
 _=filepath.WalkDir(root,func(p string,d os.DirEntry,err error)error{
   if time.Now().After(deadline){return filepath.SkipAll}
   if err!=nil{out.unreadable++;return nil}
   if d.IsDir(){
      if p!=root&&isReparse(p){return filepath.SkipDir}
      return nil
   }
   if d.Type()&os.ModeSymlink!=0||isReparse(p){return nil}
   ext:=strings.ToLower(filepath.Ext(p))
   switch ext{
   case ".exe",".dll",".sys",".ps1",".psm1",".bat",".cmd",".py",".js",".mjs",".json",".xml",".lnk",".pdf",".docm",".xlsm",".txt",".html":
   default:return nil
   }
   paths=append(paths,p)
   if len(paths)>=limit{return filepath.SkipAll}
   return nil
 })
 sort.Strings(paths)
 for _,p:=range paths{
   stat,err:=os.Lstat(p)
   if err!=nil||!stat.Mode().IsRegular(){out.unreadable++;continue}
   if stat.Size()>64*1024*1024{continue}
   flagged:=inspectFileProtected(p,stat,nil)
   ext:=strings.ToLower(filepath.Ext(p))
   totals:=out.types[ext];totals[0]++;out.scanned++
   if flagged!=nil{
     totals[1]++;out.flagged++
     t.Logf("BENIGN_FALSE_FLAG root=%s path=%q score=%d reasons=%q",label,p,flagged.Score,flagged.Reasons)
   }
   out.types[ext]=totals
 }
 keys:=make([]string,0,len(out.types));for k:=range out.types{keys=append(keys,k)};sort.Strings(keys)
 low,high:=v42Wilson(out.flagged,out.scanned)
 t.Logf("BENIGN_CORPUS_TOTAL root=%q inspected=%d flagged=%d unreadable=%d wilson95lower=%.6f wilson95upper=%.6f",label,out.scanned,out.flagged,out.unreadable,low,high)
 for _,ext:=range keys{
  v:=out.types[ext]
  t.Logf("BENIGN_CORPUS_TYPE root=%q ext=%q inspected=%d flagged=%d",label,ext,v[0],v[1])
 }
 return out
}
func TestV42WindowsRealBenignCorpusReadOnly(t *testing.T){
 roots:=[]struct{name,path string;limit int}{
  {"Windows/System32",filepath.Join(os.Getenv("WINDIR"),"System32"),2200},
  {"Windows/SysWOW64",filepath.Join(os.Getenv("WINDIR"),"SysWOW64"),1200},
  {"Program Files",os.Getenv("ProgramFiles"),1800},
  {"Program Files x86",os.Getenv("ProgramFiles(x86)"),1000},
  {"Python/stdlib",os.Getenv("SENTINELGUARD_PYTHON_ROOT"),800},
  {"npm/global",os.Getenv("SENTINELGUARD_NPM_ROOT"),800},
 }
 scanned,flagged:=0,0
 for _,root:=range roots{
  r:=v42MeasureBenignRoot(t,root.name,root.path,root.limit)
  scanned+=r.scanned;flagged+=r.flagged
 }
 low,high:=v42Wilson(flagged,scanned)
 t.Logf("BENIGN_ALL_TOTAL inspected=%d flagged=%d wilson95lower=%.6f wilson95upper=%.6f",scanned,flagged,low,high)
 if scanned<10{t.Fatal("Windows benign corpus was not actually available")}
}
func TestV42BenignFrozenWindowsHoldout(t *testing.T){
 // Predeclared file choices were frozen before reviewing results. The
 // holdout is never used to tune detector heuristics. These are only
 // expected-benign software files, not a positive-malware holdout.
 names:=[]string{"notepad.exe","cmd.exe","regedit.exe","taskmgr.exe","conhost.exe","findstr.exe",
  "whoami.exe","where.exe","netstat.exe","sc.exe","schtasks.exe","wevtutil.exe",
  "certutil.exe","more.com","fc.exe","robocopy.exe","sort.exe","ping.exe","tracert.exe","hostname.exe"}
 root:=filepath.Join(os.Getenv("WINDIR"),"System32")
 total,flagged:=0,0
 for _,name:=range names{
  p:=filepath.Join(root,name);st,err:=os.Lstat(p);if err!=nil{continue}
  if !st.Mode().IsRegular(){continue}
  total++
  f:=inspectFileProtected(p,st,nil)
  if f!=nil {flagged++;t.Logf("FROZEN_HOLDOUT_FP name=%s score=%d reasons=%v",name,f.Score,f.Reasons)}
 }
 low,high:=v42Wilson(flagged,total)
 t.Logf("FROZEN_BENIGN_HOLDOUT inspected=%d flagged=%d wilson95lower=%.6f wilson95upper=%.6f",total,flagged,low,high)
 if total<10{t.Fatalf("frozen benign Windows holdout incomplete: %d",total)}
}
var _=fmt.Sprintf
