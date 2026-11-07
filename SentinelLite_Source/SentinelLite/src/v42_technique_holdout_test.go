package main

import(
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)
func TestV42PinnedExternalTechniqueExamplesReadOnly(t *testing.T){
 folder:=os.Getenv("SENTINELGUARD_TECHNIQUE_CORPUS")
 if folder==""{t.Skip("external independent technique examples were not downloaded; no results claimed")}
 raw,err:=os.ReadFile(filepath.Join(folder,"manifest.json"))
 if err!=nil{t.Fatal(err)}
 var records []struct{
    File string `json:"file"`
    Category string `json:"category"`
    Source string `json:"source"`
    SampleSHA256 string `json:"sample_sha256"`
    Label string `json:"label"`
 }
 if err:=json.Unmarshal(raw,&records);err!=nil{t.Fatal(err)}
 if len(records)==0{t.Skip("public technique sources unavailable")}
 reviewed,found:=0,0
 for _,entry:=range records{
    if filepath.Base(entry.File)!=entry.File{t.Fatal("invalid externally provided filename")}
    p:=filepath.Join(folder,entry.File)
    st,err:=os.Lstat(p)
    if err!=nil||!st.Mode().IsRegular(){t.Fatalf("file not a regular sample: %q %v",entry.File,err)}
    b,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
    digest:=sha256.Sum256(b)
    if hex.EncodeToString(digest[:])!=entry.SampleSHA256{t.Fatal("source digest changed: "+entry.File)}
    f:=inspectFileProtected(p,st,nil)
    score:=0
    if f!=nil{score=f.Score;found++}
    reviewed++
    t.Logf("V42_TECHNIQUE_CASE category=%q source=%q name=%q sha256=%q flagged=%t score=%d",
       entry.Category,entry.Source,entry.File,entry.SampleSHA256,f!=nil,score)
 }
 t.Logf("V42_TECHNIQUE_TOTAL entries=%d flagged=%d (unvalidated technique examples, not malware verdicts)",reviewed,found)
}
