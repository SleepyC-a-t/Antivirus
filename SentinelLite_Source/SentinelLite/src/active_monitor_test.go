package main

import(
    "os"
    "path/filepath"
    "testing"
    "time"
)
func TestActiveDownloadWatcherDetectsNewStableFileAndRespectsToggle(t *testing.T) {
    dir:=t.TempDir()
    m:=newActiveMonitor(nil)
    m.watched=[]string{dir}
    hits:=0
    m.inspect=func(p string,st os.FileInfo)*Finding {
        hits++
        if filepath.Ext(p)==".exe"{
            return &Finding{Path:p,Name:filepath.Base(p),Score:80,Reasons:[]string{"inert synthetic test detection"},Size:st.Size(),Modified:st.ModTime(),CanQuarantine:true}
        }
        return nil
    }
    old:=filepath.Join(dir,"existing.exe")
    if err:=os.WriteFile(old,[]byte("existing benign bytes"),0600);err!=nil{t.Fatal(err)}
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    m.pollOnce();m.pollOnce()
    if hits!=0{t.Fatalf("existing file should be baseline only, hits=%d",hits)}
    staged:=filepath.Join(dir,"incoming.crdownload")
    if err:=os.WriteFile(staged,[]byte("inert downloaded bytes"),0600);err!=nil{t.Fatal(err)}
    m.pollOnce()
    if hits!=0{t.Fatalf("partial download incorrectly scanned")}
    completed:=filepath.Join(dir,"incoming.exe")
    if err:=os.Rename(staged,completed);err!=nil{t.Fatal(err)}
    if err:=os.Chtimes(completed,time.Now().Add(-5*time.Second),time.Now().Add(-5*time.Second));err!=nil{t.Fatal(err)}
    m.pollOnce()
    if hits!=0{t.Fatal("candidate should wait for stable observation")}
    m.pollOnce()
    snap:=m.snapshot()
    if hits!=1||snap.Flagged!=1||snap.Quarantined!=0||snap.Inspected!=1||len(snap.Events)<2{
        t.Fatalf("wrong active monitoring state: hits=%d snap=%+v",hits,snap)
    }
    if err:=m.setEnabled(false);err!=nil{t.Fatal(err)}
    another:=filepath.Join(dir,"second.exe")
    if err:=os.WriteFile(another,[]byte("second inert"),0600);err!=nil{t.Fatal(err)}
    m.pollOnce();m.pollOnce()
    if hits!=1{t.Fatal("protection off must stop new file inspection")}
}
func TestActiveSafeWatchFolderValidation(t *testing.T){
    m:=newActiveMonitor(nil)
    m.watched=nil
    if err:=m.setEnabled(true);err==nil{t.Fatal("expected missing folder error")}
    if err:=m.addFolder(t.TempDir());err!=nil{t.Fatal(err)}
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    if err:=m.addFolder("does_not_exist");err==nil{t.Fatal("expected invalid watch folder")}
    if err:=m.setEnabled(false);err!=nil{t.Fatal(err)}
}
func TestActiveOnlyAutoQuarantinesHighConfidence(t *testing.T) {
    dir:=t.TempDir()
    vaultDir:=t.TempDir()
    v:=&Vault{path:vaultDir}
    m:=newActiveMonitor(v)
    m.watched=[]string{dir}
    m.inspect=func(p string,st os.FileInfo)*Finding {
        score:=80
        if filepath.Base(p)=="high.exe"{score=120}
        return &Finding{Path:p,Name:filepath.Base(p),Score:score,Reasons:[]string{"inert test result"},Size:st.Size(),Modified:st.ModTime(),CanQuarantine:true}
    }
    m.setAutoQuarantine(true)
    if err:=m.setEnabled(true);err!=nil{t.Fatal(err)}
    for _,n:=range []string{"high.exe","review.exe"}{
        p:=filepath.Join(dir,n)
        if err:=os.WriteFile(p,[]byte("inert test data"),0600);err!=nil{t.Fatal(err)}
        earlier:=time.Now().Add(-10*time.Second)
        if err:=os.Chtimes(p,earlier,earlier);err!=nil{t.Fatal(err)}
    }
    m.pollOnce();m.pollOnce()
    s:=m.snapshot()
    if s.Inspected!=2||s.Flagged!=2||s.Quarantined!=1{t.Fatalf("unexpected auto block results: %+v",s)}
    if _,err:=os.Stat(filepath.Join(dir,"review.exe"));err!=nil{t.Fatal("Review-level finding must remain in place")}
    if _,err:=os.Stat(filepath.Join(dir,"high.exe"));!os.IsNotExist(err){t.Fatal("high confidence file should be quarantined")}
}
