package main

import (
    "path/filepath"
    "strings"
    "testing"
)

func TestSecurityExpectedWebViewRequiresTrustedLocationAndSignature(t *testing.T){
    root:=filepath.Join(t.TempDir(),"machine-managed-program-files")
    valid:=filepath.Join(root,"Microsoft","EdgeWebView","Application","155.0.4321.44","msedgewebview2.exe")
    trusted:="Trusted embedded signature (offline; revocation not checked)"
    cases:=[]struct{name,image,path,signature string;want string}{
        {"official signed runtime","msedgewebview2.exe",valid,trusted,childExpectedWebView},
        {"same file different capitalization","MSEdgeWebView2.EXE",valid,trusted,childExpectedWebView},
        {"name only with missing path","msedgewebview2.exe","",trusted,childUnverifiedWebView},
        {"spoof in sibling installation", "msedgewebview2.exe",filepath.Join(root+"-fake","Microsoft","EdgeWebView","Application","155.0.4321.44","msedgewebview2.exe"),trusted,childUnverifiedWebView},
        {"spoof in user application folder","msedgewebview2.exe",filepath.Join(root,"Acme","EdgeWebView","Application","155.0.4321.44","msedgewebview2.exe"),trusted,childUnverifiedWebView},
        {"unsigned legitimate-path lookalike","msedgewebview2.exe",valid,"Not verified (no embedded signature)",childUnverifiedWebView},
        {"signature verification timed out","msedgewebview2.exe",valid,"Not verified (native trust verification exceeded 2.5 s; no trust granted)",childUnverifiedWebView},
        {"invalid version subfolder","msedgewebview2.exe",filepath.Join(root,"Microsoft","EdgeWebView","Application","latest","msedgewebview2.exe"),trusted,childUnverifiedWebView},
        {"incorrect executable extension","msedgewebview2.exe",filepath.Join(root,"Microsoft","EdgeWebView","Application","155.0.4321.44","msedgewebview2.exe.bak"),trusted,childUnverifiedWebView},
        {"non-runtime Edge executable","msedgewebview2.exe",filepath.Join(root,"Microsoft","Edge","Application","155.0.4321.44","msedgewebview2.exe"),trusted,childUnverifiedWebView},
        {"unexpected PowerShell","powershell.exe",valid,trusted,childUnexpected},
        {"unexpected CMD","cmd.exe",valid,trusted,childUnexpected},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            got,reason:=classifyChildEvidence(tc.image,tc.path,tc.signature,[]string{root})
            if got!=tc.want{t.Fatalf("classification %q, want %q (%s)",got,tc.want,reason)}
            if strings.TrimSpace(reason)==""{t.Fatal("classification lacked explanation")}
        })
    }
}

func TestSecurityTrustedWebViewPolicyRejectsUntrustedRoots(t *testing.T){
    root:=filepath.Join(t.TempDir(),"official-root")
    target:=filepath.Join(root,"Microsoft","EdgeWebView","Application","155.0.1.2","msedgewebview2.exe")
    trusted:="Trusted embedded signature (offline; revocation not checked)"
    got,_:=classifyChildEvidence("msedgewebview2.exe",target,trusted,nil)
    if got==childExpectedWebView{t.Fatal("missing machine registry roots must never suppress a warning")}
}

func TestSecurityChildReviewCountAndWarningAreConservative(t *testing.T){
    a:=newApp(nil)
    a.status=Status{Active:true,Mode:"heuristic:full"}
    a.childSeen=make(map[observedChildIdentity]ObservedChildProcess)
    a.recordClassifiedChildLocked(ObservedChildProcess{
        PID:2232,ParentPID:7924,Image:"msedgewebview2.exe",
        CreationTimeTicks:101,Classification:childExpectedWebView,
    })
    a.reconcileChildWarningLocked()
    if a.status.ChildProcessesObserved!=1 || a.status.ChildProcessesExpected!=1 ||
       a.status.ChildProcessesUnexpected!=0 || a.status.ChildProcessWarning!=""{
        t.Fatalf("verified WebView child must be recorded without heuristic warning: %+v",a.status)
    }
    a.recordClassifiedChildLocked(ObservedChildProcess{
        PID:2232,ParentPID:7924,Image:"msedgewebview2.exe",
        CreationTimeTicks:101,Classification:childExpectedWebView,
    })
    if a.status.ChildProcessesObserved!=1 {t.Fatal("same native process identity double-counted")}
    a.recordClassifiedChildLocked(ObservedChildProcess{
        PID:2232,ParentPID:7924,Image:"powershell.exe",
        CreationTimeTicks:102,Classification:childUnexpected,
    })
    a.reconcileChildWarningLocked()
    if a.status.ChildProcessesObserved!=2||a.status.ChildProcessesUnexpected!=1||
       a.status.ChildProcessWarning==""{
        t.Fatalf("PID reuse of a different process must trigger the warning: %+v",a.status)
    }
    a.recordClassifiedChildLocked(ObservedChildProcess{
        PID:2300,ParentPID:7924,Image:"msedgewebview2.exe",
        CreationTimeTicks:103,Classification:childUnverifiedWebView,
    })
    a.reconcileChildWarningLocked()
    if a.status.ChildProcessesUnexpected!=2 || len(a.status.ChildProcessEntries)!=3{
        t.Fatal("unsigned WebView lookalike was suppressed or omitted")
    }
}
