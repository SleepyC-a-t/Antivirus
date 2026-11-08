package main

import ("testing")

// The tripwire is reset on each scan. It is OS-observed on Windows; a separate
// Windows-only integration test launches a harmless sleeping helper.
func TestSecurityChildProcessCounterIsPerScanAndExported(t *testing.T) {
    a:=newApp(nil)
    if _,err:=a.begin("heuristic:custom");err!=nil{t.Fatal(err)}
    a.mu.RLock()
    done:=a.resourceDone
    a.mu.RUnlock()
    a.sampleChildProcesses(done)
    if s,_:=a.snapshot();s.ChildProcessesObserved!=0 {
        t.Fatalf("fresh passive scan had unexpected observed children: %+v",s.ChildProcessEntries)
    }
    a.finish(nil)
    if _,err:=a.begin("heuristic:quick");err!=nil{t.Fatal(err)}
    if s,_:=a.snapshot();s.ChildProcessesObserved!=0||len(s.ChildProcessEntries)!=0 {
        t.Fatalf("new scan retained the previous child-process observations: %+v",s)
    }
    a.finish(nil)
}
