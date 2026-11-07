package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
type externalEvalLabel struct{
 File string `json:"file"`
 Label string `json:"label"`
}
type externalEvalCounts struct{
 TP int `json:"tp"`
 FN int `json:"fn"`
 FP int `json:"fp"`
 TN int `json:"tn"`
 Skipped int `json:"skipped"`
}
func evaluateLabeledCorpus(root string)(externalEvalCounts,error){
 var counts externalEvalCounts
 dir,err:=filepath.Abs(root);if err!=nil{return counts,err}
 stat,err:=os.Lstat(dir);if err!=nil{return counts,err}
 if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0||isReparse(dir){return counts,errors.New("corpus root must be a non-symlink directory")}
 keyPath:=filepath.Join(dir,"labels.json")
 file,err:=os.Open(keyPath);if err!=nil{return counts,err}
 defer file.Close()
 stat,err=file.Stat();if err!=nil{return counts,err}
 if stat.Size()<2||stat.Size()>1024*1024{return counts,errors.New("labels.json is empty or too large")}
 var samples []externalEvalLabel
 if err=json.NewDecoder(file).Decode(&samples);err!=nil{return counts,err}
 if len(samples)==0||len(samples)>5000{return counts,errors.New("corpus requires between 1 and 5000 labeled files")}
 seen:=map[string]bool{}
 for _,entry:=range samples{
    relative:=filepath.Clean(filepath.FromSlash(entry.File))
    if entry.File==""||filepath.IsAbs(relative)||relative=="."||relative==".."||strings.HasPrefix(relative,".."+string(filepath.Separator)){
       return counts,fmt.Errorf("invalid corpus path %q",entry.File)
    }
    if seen[relative]{return counts,fmt.Errorf("duplicate label path: %q",entry.File)}
    seen[relative]=true
    if entry.Label!="suspicious"&&entry.Label!="benign"{return counts,fmt.Errorf("invalid label for %q",entry.File)}
    path:=filepath.Join(dir,relative)
    // Refuse links in any parent component to avoid following sample
    // pointers to unrelated Windows/system files.
    cur:=dir
    parts:=strings.Split(relative,string(filepath.Separator))
    for _,part:=range parts{
       cur=filepath.Join(cur,part)
       st,err:=os.Lstat(cur);if err!=nil{return counts,err}
       if st.Mode()&os.ModeSymlink!=0||isReparse(cur){return counts,fmt.Errorf("linked sample path forbidden: %q",entry.File)}
    }
    st,err:=os.Lstat(path)
    if err!=nil{return counts,err}
    if !st.Mode().IsRegular(){return counts,fmt.Errorf("not a regular file: %q",entry.File)}
    f:=inspectFileProtected(path,st,nil)
    flagged:=f!=nil
    if entry.Label=="suspicious"{
       if flagged{counts.TP++}else{counts.FN++}
    }else if flagged{counts.FP++}else{counts.TN++}
 }
 return counts,nil
}
// Optional: place externally sourced, INERT files and labels.json in a
// separate folder, then run:
// SENTINELGUARD_EXTERNAL_CORPUS=/path/to/holdout go test -run TestV41ExternalLabeledCorpus -v
// The test only reads samples and never executes any of them.
func TestV41ExternalLabeledCorpus(t *testing.T){
 root:=os.Getenv("SENTINELGUARD_EXTERNAL_CORPUS")
 if root==""{t.Skip("no independent corpus provided; do not fabricate real-world detection results")}
 result,err:=evaluateLabeledCorpus(root)
 if err!=nil{t.Fatal(err)}
 t.Logf("EXTERNAL_HOLDOUT TP=%d FN=%d FP=%d TN=%d",result.TP,result.FN,result.FP,result.TN)
}
func TestV41ExternalCorpusHarnessSafety(t *testing.T){
 dir:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(dir,"suspicious.pdf.exe"),[]byte("inert fixture"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,"normal.txt"),[]byte("hello"),0600);err!=nil{t.Fatal(err)}
 writeLabels:=func(s string){t.Helper();if err:=os.WriteFile(filepath.Join(dir,"labels.json"),[]byte(s),0600);err!=nil{t.Fatal(err)}}
 writeLabels(`[{"file":"suspicious.pdf.exe","label":"suspicious"},{"file":"normal.txt","label":"benign"}]`)
 result,err:=evaluateLabeledCorpus(dir)
 if err!=nil{t.Fatal(err)}
 if result.TP!=1||result.TN!=1||result.FP!=0||result.FN!=0{t.Fatalf("unexpected harness count %+v",result)}
 writeLabels(`[{"file":"../outside.exe","label":"suspicious"}]`)
 if _,err:=evaluateLabeledCorpus(dir);err==nil{t.Fatal("traversal was accepted")}
 writeLabels(`[{"file":"normal.txt","label":"malicious"}]`)
 if _,err:=evaluateLabeledCorpus(dir);err==nil{t.Fatal("unknown label was accepted")}
}
