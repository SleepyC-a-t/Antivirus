package main

import ("testing")

// Child processes are accounted for only when an external helper was
// intentionally launched (Defender mode); no scan file is ever executed.
func TestSecurityChildProcessCounterIsPerScanAndExported(t *testing.T){
 a:=newApp(nil)
 ctx,err:=a.begin("heuristic:custom")
 if err!=nil{t.Fatal(err)}
 if got,_:=a.snapshot();got.ChildProcessesStarted!=0{
  t.Fatalf("new passive scan had %d child processes",got.ChildProcessesStarted)
 }
 a.recordChildStarted()
 if got,_:=a.snapshot();got.ChildProcessesStarted!=1{
  t.Fatalf("app-initiated helper process not accounted: %d",got.ChildProcessesStarted)
 }
 a.finish(nil)
 if _,err:=a.begin("heuristic:quick");err!=nil{t.Fatal(err)}
 if got,_:=a.snapshot();got.ChildProcessesStarted!=0{
  t.Fatalf("new scan retained old child count: %d",got.ChildProcessesStarted)
 }
 a.finish(ctx.Err())
}
