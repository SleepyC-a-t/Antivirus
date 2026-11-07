package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestSafeLaunchOptInApprovalAuditAndNoExecutionByDefault(t *testing.T){
    folder:=t.TempDir()
    p:=filepath.Join(folder,"invoice.pdf.exe")
    if err:=os.WriteFile(p,[]byte("MZ inert simulated executable, never executed"),0600);err!=nil{t.Fatal(err)}
    m:=newActiveMonitor(nil)
    m.watched=[]string{folder}
    m.inspect=func(path string,info os.FileInfo)*Finding{
        return &Finding{Path:path,Score:72,Reasons:[]string{"inert simulated risky program"},CanQuarantine:true}
    }
    invoked:=0
    launch:=func(string)error{invoked++;return nil}
    if _,err:=m.safeLaunchProgram(p,func(string,int,[]string)bool{return true},launch);err==nil{
        t.Fatal("safe launch must be disabled by default")
    }
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    if _,err:=m.safeLaunchProgram(p,func(string,int,[]string)bool{return true},launch);err==nil {
        t.Fatal("safe launch must need its separate opt-in")
    }
    if err:=m.setSafeLaunch(true);err!=nil{t.Fatal(err)}
    denied,err:=m.safeLaunchProgram(p,func(string,int,[]string)bool{return false},launch)
    if err!=nil||denied.Started||invoked!=0||denied.Decision!="cancelled"{t.Fatalf("declined warning must not launch: %+v %v",denied,err)}
    accepted,err:=m.safeLaunchProgram(p,func(string,int,[]string)bool{return true},launch)
    if err!=nil||!accepted.Started||invoked!=1 {t.Fatalf("accepted launch not reached: %+v %v",accepted,err)}
    st:=m.snapshot()
    if st.LaunchChecks!=2||st.LaunchApproved!=1||st.LaunchDenied!=1||len(st.LaunchEvents)<3 {
        t.Fatalf("launch auditing incomplete: %+v",st)
    }
    if err:=m.setEnabled(false);err!=nil{t.Fatal(err)}
    if m.snapshot().SafeLaunch{t.Fatal("turning OFF protection must disable safe-launch too")}
    if _,err:=m.safeLaunchProgram(p,nil,launch);err==nil{t.Fatal("OFF must block launch")}
}
func TestSafeLaunchFileChangeBlocksExecution(t *testing.T){
    folder:=t.TempDir()
    p:=filepath.Join(folder,"invoice.pdf.exe")
    if err:=os.WriteFile(p,[]byte("MZ 12345"),0600);err!=nil{t.Fatal(err)}
    m:=newActiveMonitor(nil);m.watched=[]string{folder}
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    if err:=m.setSafeLaunch(true);err!=nil{t.Fatal(err)}
    launched:=false
    result,err:=m.safeLaunchProgram(p,func(string,int,[]string)bool{
        _=os.WriteFile(p,[]byte("MZ changed after warning"),0600)
        return true
    },func(string)error{launched=true;return nil})
    if err==nil || launched || result.Started || result.Decision!="blocked" {
        t.Fatalf("changed executable was allowed: result=%+v err=%v launched=%t",result,err,launched)
    }
    snap:=m.snapshot()
    if snap.LaunchDenied!=1 || snap.LaunchApproved!=0 {
        t.Fatalf("mutation was not logged as denied: %+v",snap)
    }
}
func TestSafeLaunchRejectsNonExePaths(t *testing.T){
    if _,_,err:=verifyExecutable(filepath.Join(t.TempDir(),"script.ps1"));err==nil{
        t.Fatal("must not launch scripts")
    }
    m:=newActiveMonitor(nil)
    if m.snapshot().SafeLaunch {t.Fatal("safe launch should begin OFF")}
}
