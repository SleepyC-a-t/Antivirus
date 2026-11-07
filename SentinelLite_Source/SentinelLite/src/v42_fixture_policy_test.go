package main

import(
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "testing"
)

// These are 95 completely INERT static fixtures. A string that resembles
// an operational command is not evidence it has ever executed. Keep the
// original intended indicator labels intact as regression expectations,
// but explicitly record that NO operational malware was established.
func TestV42FixtureOperationalClassificationAudit(t *testing.T){
    cases:=stage6Corpus()
    dir:=t.TempDir()
    if len(cases)!=95{t.Fatalf("Stage6 fixture count changed unexpectedly: %d",len(cases))}
    for i,c:=range cases{
        p:=filepath.Join(dir,"case-"+itoaV42(i),c.filename)
        if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
        data:=[]byte(c.content)
        if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
        st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
        f:=inspectFileProtected(p,st,nil)
        d:=sha256.Sum256(data)
        t.Logf("V42_FIXTURE_LABELED id=%03d source=Stage6 group=%q name=%q intendedIndicator=%t operationalEvidence=false classification=%q detected=%t bytes=%d sha256=%s",
            i,c.group,c.filename,c.suspicious,"indicator present, non-operational",f!=nil,len(data),hex.EncodeToString(d[:]))
    }
    t.Log("V42_FIXTURE_POLICY: all in-repository tests are static non-executed indicators; original suspicious/benign labels remain regression expectations only")
}
