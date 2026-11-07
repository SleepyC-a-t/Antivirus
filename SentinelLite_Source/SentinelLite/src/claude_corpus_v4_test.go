package main

import (
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
    "time"
)

type claudeExpectedSample struct {
    Filename string `json:"filename"`
    ExpectedClassification string `json:"expected_classification"`
    SimulatedThreatCategory string `json:"simulated_threat_category"`
}

// This executes only the audited Python FIXTURE GENERATOR, not any file it
// creates. Every .ps1, .bat, .exe, .bas, .py, .js and archive is inspected as
// inert bytes by the scanner; no subprocess ever executes a generated sample.
func TestV4ActiveClaudeFullInertDownloadSimulation(t *testing.T) {
    python,err:=exec.LookPath("python")
    if err!=nil {t.Skip("Python is required for this optional exact-corpus test")}
    temp:=t.TempDir()
    watchDir:=filepath.Join(temp,"Antivirus_Test_Corpus")
    if err:=os.MkdirAll(watchDir,0700);err!=nil{t.Fatal(err)}
    monitor:=newActiveMonitor(nil)
    monitor.watched=[]string{watchDir}
    if monitor.snapshot().Enabled || monitor.snapshot().AutoQuarantine {
        t.Fatal("Active protection AND auto-quarantine must both default to OFF")
    }
    seen:=map[string]*Finding{}
    monitor.inspect=func(p string,st os.FileInfo)*Finding {
        f:=inspectFileProtected(p,st,nil)
        seen[filepath.Base(p)]=f
        return f
    }
    if err:=monitor.setEnabled(true);err!=nil{t.Fatal(err)}
    // The script is from the user's own attachment, previously reviewed and
    // committed under testdata. It writes ONLY inert sample data to temp.
    generator:=filepath.Join("testdata","claude_inert_generator.py")
    absolute,err:=filepath.Abs(generator)
    if err!=nil{t.Fatal(err)}
    cmd:=exec.Command(python,absolute)
    cmd.Dir=temp
    output,err:=cmd.CombinedOutput()
    if err!=nil{t.Fatalf("inert corpus generator failed: %s %v",output,err)}
    answer,err:=os.ReadFile(filepath.Join(watchDir,"answer_key.json"))
    if err!=nil{t.Fatal(err)}
    var keys []claudeExpectedSample
    if err=json.Unmarshal(answer,&keys);err!=nil{t.Fatal(err)}
    if len(keys)!=24 {t.Fatalf("expected 24 exact Claude sample files; got %d",len(keys))}
    // Simulate a completed browser download: files have stable timestamps and
    // no browser partial-file extensions. This mirrors Chrome/Firefox rename
    // from .crdownload/.part to their final names.
    old:=time.Now().Add(-12*time.Second)
    for _,sample:=range keys {
        p:=filepath.Join(watchDir,sample.Filename)
        if err:=os.Chtimes(p,old,old);err!=nil{t.Fatalf("timestamp %q: %v",p,err)}
    }
    if err:=os.Chtimes(filepath.Join(watchDir,"answer_key.json"),old,old);err!=nil{t.Fatal(err)}
    monitor.pollOnce()
    if monitor.snapshot().Inspected!=0 {t.Fatal("new writes must wait for stable observation")}
    monitor.pollOnce()
    monitor.pollOnce() // no duplicate scanning
    stats:=monitor.snapshot()
    if stats.Inspected!=int64(len(keys)+1) {
        t.Fatalf("expected 24 samples + answer key inspected exactly once, got %+v",stats)
    }
    if stats.Quarantined!=0 {t.Fatalf("auto-quarantine was unexpectedly enabled: %+v",stats)}
    tp,fn,fp,tn:=0,0,0,0
    detected:=map[string]bool{}
    for _,item:=range keys {
        finding:=seen[item.Filename]
        isDetected:=finding!=nil
        detected[item.Filename]=isDetected
        if item.ExpectedClassification=="suspicious" {
            if isDetected {tp++} else {fn++}
        }else if item.ExpectedClassification=="benign"{
            if isDetected {fp++} else {tn++}
        }else{t.Fatalf("unexpected class: %q",item.ExpectedClassification)}
        score:=0
        reasons:=""
        if finding!=nil{score=finding.Score;reasons=strings.Join(finding.Reasons," | ")}
        t.Logf("CLAUDE_V4 file=%s class=%s detected=%t score=%d reason=%q",
            item.Filename,item.ExpectedClassification,isDetected,score,reasons)
        if _,err:=os.Stat(filepath.Join(watchDir,item.Filename));err!=nil{
            t.Fatalf("simulated download should still be present: %s: %v",item.Filename,err)
        }
    }
    if len(seen)!=25 {t.Fatalf("not all completed files inspected; got %d",len(seen))}
    if tp+fn!=16||fp+tn!=8{t.Fatalf("wrong answer key composition: TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)}
    t.Logf("CLAUDE_V4_TOTAL platform=%s TP=%d FN=%d FP=%d TN=%d inspected=%d",
       runtime.GOOS,tp,fn,fp,tn,stats.Inspected)
    for _,name:=range []string{
        "README_RESTORE_FILES.txt","SystemHealthTask.xml","Invoice_2026_0042.pdf.exe","invoice_bundle.zip",
    }{
        if !detected[name]{t.Errorf("regression: established inert indicator not flagged: %s",name)}
    }
    if fp>0{t.Errorf("benign-control regression: %d of 8 flagged",fp)}
    if err:=monitor.setEnabled(false);err!=nil{t.Fatal(err)}
    newPath:=filepath.Join(watchDir,"later_file.exe")
    if err:=os.WriteFile(newPath,[]byte("MZ inert OFF-switch control"),0600);err!=nil{t.Fatal(err)}
    monitor.pollOnce();monitor.pollOnce()
    if monitor.snapshot().Inspected!=stats.Inspected{t.Error("OFF switch failed: downloaded file was inspected while disabled")}
}
