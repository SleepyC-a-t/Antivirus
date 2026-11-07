package main
import(
 "os"
 "path/filepath"
 "runtime"
 "testing"
)
func TestV41IndependentOSBenignExecutables(t *testing.T){
 if runtime.GOOS!="windows"{t.Skip("Windows benign control benchmark only")}
 root:=os.Getenv("WINDIR")
 if root==""{t.Skip("Windows path unavailable")}
 names:=[]string{"notepad.exe","cmd.exe","regedit.exe","conhost.exe","taskmgr.exe"}
 tested,flagged:=0,0
 for _,name:=range names{
    p:=filepath.Join(root,"System32",name)
    st,err:=os.Stat(p)
    if err!=nil {t.Logf("not installed: %s",name);continue}
    finding:=inspectFileProtected(p,st,nil)
    tested++
    if finding!=nil {flagged++;t.Logf("INDEPENDENT_BENIGN false positive file=%s score=%d reasons=%v",name,finding.Score,finding.Reasons)}
 }
 if tested==0{t.Fatal("no Windows executables tested")}
 t.Logf("INDEPENDENT_BENIGN_TOTAL windows=%d flagged=%d",tested,flagged)
 if flagged>0{t.Fatalf("benign Windows system executables flagged: %d/%d",flagged,tested)}
}
// EICAR is an external, published antivirus TEST SIGNATURE, not malware.
// Existing TestStage9EICAR verifies its behavior in the same full suite.
