package main

import(
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "testing"
)

// Read-only independent technique definitions are not automatically positive
// malware labels; the scanner never runs a downloaded command or binary.
func TestV42IndependentTechniqueDefinitionsStaticOnly(t *testing.T){
 root:=os.Getenv("SENTINELGUARD_TECHNIQUE_DEFINITIONS")
 if root==""{t.Skip("independent definitions unavailable")}
 entries,err:=os.ReadDir(root);if err!=nil{t.Skip(err)}
 var names []string
 for _,e:=range entries{if !e.IsDir(){names=append(names,e.Name())}}
 sort.Strings(names)
 checked,flagged:=0,0
 for _,name:=range names{
  if checked>=100 {break}
  p:=filepath.Join(root,name);info,err:=os.Lstat(p)
  if err!=nil||!info.Mode().IsRegular()||info.Size()>1024*1024{continue}
  buf,err:=os.ReadFile(p);if err!=nil{continue}
  digest:=sha256.Sum256(buf)
  f:=inspectFileProtected(p,info,nil)
  score:=0;reasons:=""
  if f!=nil{flagged++;score=f.Score;reasons=strings.Join(f.Reasons," | ")}
  checked++
  t.Logf("INDEPENDENT_TECHNIQUE name=%q bytes=%d sha256=%s detected=%t score=%d reasons=%q",
    name,len(buf),hex.EncodeToString(digest[:]),f!=nil,score,reasons)
 }
 t.Logf("INDEPENDENT_TECHNIQUE_TOTAL examined=%d flagged=%d expectedLabels=none",checked,flagged)
 if checked==0{t.Skip("external technique files were not available")}
}
