package main

import (
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Reuse the original Stage 6 fixture generator without modifying the
// detector. Log EVERY sample, including the ones correctly rejected as
// benign and suspicious misses. This is read-only static file inspection.
// This test supplies granular results for the external reviewer report.
func TestPublicDetailedStage6Labels(t *testing.T){
 cases:=stage6Corpus()
 if len(cases)!=95 {t.Fatalf("unexpected Stage 6 corpus length: %d",len(cases))}
 dir:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for index,c:=range cases {
   p:=filepath.Join(dir,fmt.Sprintf("case-%03d",index),c.filename)
   if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
   data:=[]byte(c.content)
   if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
   stat,err:=os.Lstat(p);if err!=nil{t.Fatal(err)}
   finding:=inspectFileProtected(p,stat,nil)
   flagged:=finding!=nil
   if c.suspicious{
      if flagged{tp++}else{fn++}
   }else if flagged{fp++}else{tn++}
   score,reasons:=0,""
   if finding!=nil {score=finding.Score;reasons=strings.Join(finding.Reasons," | ")}
   digest:=sha256.Sum256(data)
   t.Logf("PUBLIC_STAGE6_CASE id=%03d group=%q label=%q name=%q expected=%t detected=%t score=%d bytes=%d sha256=%s reasons=%q",
     index,c.group,c.label,c.filename,c.suspicious,flagged,score,len(data),hex.EncodeToString(digest[:]),reasons)
 }
 t.Logf("PUBLIC_STAGE6_TOTAL TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
 if tp+fn!=65||fp+tn!=30{t.Fatal("Stage6 case labels were not preserved")}
}
