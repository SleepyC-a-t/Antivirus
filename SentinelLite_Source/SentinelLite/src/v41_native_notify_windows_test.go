//go:build windows
package main

import(
 "context"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func TestV41WindowsNotifierWakesOnNewDownload(t *testing.T){
 dir:=t.TempDir()
 kick:=make(chan struct{},4)
 ctx,cancel:=context.WithCancel(context.Background())
 defer cancel()
 go watchActiveDirectory(ctx,dir,kick)
 // Allow the kernel notification handle to be armed.
 time.Sleep(250*time.Millisecond)
 p:=filepath.Join(dir,"fresh_download.txt")
 if err:=os.WriteFile(p,[]byte("benign inert download"),0600);err!=nil{t.Fatal(err)}
 select{
 case <-kick:
 case <-time.After(6*time.Second):t.Fatal("Windows native filesystem notification did not signal file creation")
 }
}
