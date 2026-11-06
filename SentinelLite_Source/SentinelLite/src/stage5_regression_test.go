package main

import (
 "os"
 "path/filepath"
 "testing"
)

func TestStage5OmittedFindingsReportAndReset(t *testing.T) {
 a:=newApp(nil)
 for i:=0;i<3100;i++ {a.add(Finding{Path:"synthetic",Score:70})}
 status,items:=a.snapshot()
 if len(items)!=3000 || status.Findings!=3000 || status.Omitted!=100 {
  t.Fatalf("want 3000 findings and 100 explicitly reported as omitted; got findings=%d length=%d omitted=%d",status.Findings,len(items),status.Omitted)
 }
 _,err:=a.begin("heuristic:custom")
 if err!=nil {t.Fatal(err)}
 status,_=a.snapshot()
 if status.Omitted!=0 {t.Fatalf("new scan must reset omitted count: %d",status.Omitted)}
 a.stop()
 a.finish(nil)
}
func TestStage5ReviewHashAndChangedBytes(t *testing.T) {
 d:=t.TempDir()
 v:=&Vault{path:filepath.Join(d,"quarantine")}
 if err:=os.MkdirAll(v.path,0700);err!=nil{t.Fatal(err)}
 p:=filepath.Join(d,"review.pdf.exe")
 if err:=os.WriteFile(p,[]byte("original00"),0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(p)
 finding:=inspectFile(p,st)
 if finding==nil||finding.ReviewSHA256=="" {t.Fatal("findings must record a review SHA-256")}
 if err:=os.WriteFile(p,[]byte("different0"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Chtimes(p,st.ModTime(),st.ModTime());err!=nil{t.Fatal(err)}
 if _,err:=v.quarantine(*finding);err==nil {t.Fatal("quarantine accepted content changed since initial scan")}
 if _,err:=os.Stat(p);err!=nil {t.Fatalf("original file was lost: %v",err)}
}
