package main

import(
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)
func makeInertPE(t *testing.T,p string) {
    t.Helper()
    data:=make([]byte,512)
    copy(data,[]byte("MZ"))
    // Inert minimal PE-shaped bytes: PE signature offset 0x80. This is not a runnable program.
    data[0x3c]=0x80
    copy(data[0x80:],[]byte{'P','E',0,0})
    copy(data[160:],[]byte("Synthetic harmless PE-shaped fixture; never executed"))
    if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
}
func TestV41ScanAndRunRequiresIndependentOptInAndOneTimeApproval(t *testing.T){
    p:=filepath.Join(t.TempDir(),"safe.exe")
    makeInertPE(t,p)
    monitor:=newActiveMonitor(nil)
    monitor.watched=[]string{filepath.Dir(p)}
    server:=&Server{active:monitor}
    launches:=0
    server.launchRunner=func(s string)error{launches++;if s!=p{t.Fatalf("launched unexpected path: %q",s)};return nil}
    if _,err:=server.beginLaunchReview(p);err==nil{t.Fatal("launch review must be disabled at startup")}
    monitor.setLaunchReview(true)
    if _,err:=server.beginLaunchReview(p);err==nil{t.Fatal("launch review requires active scanner ON")}
    if err:=monitor.setEnabled(true);err!=nil{t.Fatal(err)}
    review,err:=server.beginLaunchReview(p)
    if err!=nil{t.Fatal(err)}
    if review.Ticket==""||review.Path!=p{t.Fatalf("invalid review: %+v",review)}
    if launches!=0{t.Fatal("program ran before user approval")}
    if err:=server.decideLaunch(review.Ticket,false);err!=nil{t.Fatal(err)}
    if launches!=0{t.Fatal("user denial must not launch a program")}
    if err:=server.decideLaunch(review.Ticket,true);err==nil{t.Fatal("ticket replay must fail")}
    approved,err:=server.beginLaunchReview(p)
    if err!=nil{t.Fatal(err)}
    if err:=server.decideLaunch(approved.Ticket,true);err!=nil{t.Fatal(err)}
    if launches!=1{t.Fatal("approved program should launch exactly once")}
    if err:=server.decideLaunch(approved.Ticket,true);err==nil{t.Fatal("approval ticket reused")}
    st:=monitor.snapshot()
    if st.LaunchReviews!=2||st.LaunchAllowed!=1||st.LaunchDenied!=1{t.Fatalf("incorrect launch metrics %+v",st)}
    haveCancel,haveApproval:=false,false
    for _,e:=range st.Events{
        if e.Action=="launch-cancelled"{haveCancel=true}
        if e.Action=="launch-approved"{haveApproval=true}
    }
    if !haveCancel||!haveApproval{t.Fatalf("launch actions absent from JSON audit: %+v",st.Events)}
}
func TestV41ScanAndRunRejectsChangedExecutableAndExpiredReviews(t *testing.T){
    dir:=t.TempDir();p:=filepath.Join(dir,"sample.exe")
    makeInertPE(t,p)
    m:=newActiveMonitor(nil);m.watched=[]string{dir};_ = m.setEnabled(true);m.setLaunchReview(true)
    launches:=0;s:=&Server{active:m,launchRunner:func(string)error{launches++;return nil}}
    r,err:=s.beginLaunchReview(p);if err!=nil{t.Fatal(err)}
    bytes,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
    bytes[180]^=0x23
    if err=os.WriteFile(p,bytes,0600);err!=nil{t.Fatal(err)}
    if err:=s.decideLaunch(r.Ticket,true);err==nil||!strings.Contains(err.Error(),"changed"){t.Fatalf("changed file accepted: %v",err)}
    if launches!=0{t.Fatal("changed executable was run")}
    r2,err:=s.beginLaunchReview(p);if err!=nil{t.Fatal(err)}
    s.launchMu.Lock();v:=s.launchTickets[r2.Ticket];v.Expires=time.Now().Add(-time.Second);s.launchTickets[r2.Ticket]=v;s.launchMu.Unlock()
    if err:=s.decideLaunch(r2.Ticket,true);err==nil{t.Fatal("expired launch ticket was approved")}
    m.setLaunchReview(false)
    if _,err:=s.beginLaunchReview(p);err==nil{t.Fatal("review should be disabled after toggle")}
    if launches!=0{t.Fatal("unexpected program execution")}
}
func TestV41ScanAndRunRejectsWrongFileTypes(t *testing.T){
    dir:=t.TempDir()
    for _,n:=range []string{"startup.ps1","shortcut.lnk","fake.exe"} {
        p:=filepath.Join(dir,n)
        if err:=os.WriteFile(p,[]byte("not executable"),0600);err!=nil{t.Fatal(err)}
        if _,_,err:=reviewedExecutable(p);err==nil{t.Fatalf("accepted invalid executable %q",n)}
    }
}
func TestV41RecentCleanInspectionsAreAudited(t *testing.T){
    dir:=t.TempDir();m:=newActiveMonitor(nil);m.watched=[]string{dir}
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    p:=filepath.Join(dir,"benign_photo.jpg")
    if err:=os.WriteFile(p,[]byte("sample test photo harmless"),0600);err!=nil{t.Fatal(err)}
    old:=time.Now().Add(-5*time.Second);_ = os.Chtimes(p,old,old)
    m.pollOnce();m.pollOnce()
    snap:=m.snapshot()
    if snap.Inspected!=1{t.Fatalf("expected one inspection %+v",snap)}
    found:=false
    for _,event:=range snap.Events{if event.Action=="inspected-clean"&&event.Path==p{found=true}}
    if !found{t.Fatal("clean file path missing from audit events")}
}
