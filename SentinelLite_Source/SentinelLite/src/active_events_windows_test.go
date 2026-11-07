//go:build windows

package main

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

// Verify that the native ReadDirectoryChangesW watcher really receives
// filesystem events on Windows, not merely that its source compiles.
func TestWindowsDirectoryChangeNotification(t *testing.T){
    dir:=t.TempDir()
    events:=make(chan struct{},2)
    stop:=startFileChangeWatcher([]string{dir},events)
    defer stop()
    p:=filepath.Join(dir,"sample.txt")
    if err:=os.WriteFile(p,[]byte("harmless watch-test data"),0600);err!=nil{t.Fatal(err)}
    select{
    case <-events:
    case <-time.After(7*time.Second):
        t.Fatal("ReadDirectoryChangesW failed to deliver a file creation notification")
    }
}

// End-to-end check that an ON live monitor sees a new inert downloaded file,
// without any test explicitly invoking pollOnce().
func TestWindowsEventDrivenLiveInspection(t *testing.T){
    dir:=t.TempDir()
    m:=newActiveMonitor(nil)
    m.watched=[]string{dir}
    m.start()
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    defer m.setEnabled(false)
    time.Sleep(400*time.Millisecond) // allow watcher subscription
    p:=filepath.Join(dir,"harmless_download.txt")
    if err:=os.WriteFile(p,[]byte("simple harmless temporary test content"),0600);err!=nil{t.Fatal(err)}
    old:=time.Now().Add(-10*time.Second)
    if err:=os.Chtimes(p,old,old);err!=nil{t.Fatal(err)}
    until:=time.Now().Add(16*time.Second)
    for time.Now().Before(until){
        stats:=m.snapshot()
        if stats.Inspected>=1{
            found:=false
            for _,event:=range stats.Events{
                if event.Path==p && event.Action=="clean"{found=true;break}
            }
            if !found{t.Fatal("download was counted but its clean-file audit event is missing")}
            return
        }
        time.Sleep(250*time.Millisecond)
    }
    t.Fatal("live monitor did not inspect a settled file after Windows event notification")
}
