package main

import (
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

const maxReviewExecutableSize=256*1024*1024
type launchTicket struct {
    Path string
    Digest string
    Size int64
    Expires time.Time
    Score int
    Signature string
    Publisher string
    Zone string
    InternetZone bool
}
type LaunchReview struct {
    Ticket string `json:"ticket"`
    Path string `json:"path"`
    Score int `json:"score"`
    Severity string `json:"severity"`
    Reasons []string `json:"reasons"`
    ExpiresAt time.Time `json:"expiresAt"`
    Warning string `json:"warning"`
    SHA256 string `json:"sha256"`
    Size int64 `json:"size"`
    Authenticode string `json:"authenticode"`
    Publisher string `json:"publisher"`
    Zone string `json:"zone"`
    InternetZone bool `json:"internetZone"`
    Inspection string `json:"inspection"`
}
func reviewedExecutable(path string)(string,os.FileInfo,error){
    p,err:=filepath.Abs(filepath.Clean(path))
    if err!=nil{return "",nil,err}
    if strings.HasPrefix(p,`\\`){return "",nil,errors.New("network executables are not eligible for Scan & Run")}
    if !strings.EqualFold(filepath.Ext(p),".exe"){return "",nil,errors.New("Scan & Run accepts only .exe; script/shortcut launching is not supported")}
    st,err:=os.Lstat(p)
    if err!=nil{return "",nil,err}
    if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0||isReparse(p){
        return "",nil,errors.New("file must be a regular executable, not a link or reparse point")
    }
    if st.Size()<64||st.Size()>maxReviewExecutableSize{return "",nil,errors.New("executable size is outside the review limit")}
    f,err:=os.Open(p)
    if err!=nil{return "",nil,err}
    defer f.Close()
    magic:=make([]byte,2)
    if _,err:=io.ReadFull(f,magic);err!=nil{return "",nil,err}
    if string(magic)!="MZ"{return "",nil,errors.New("not a Windows PE executable (missing MZ header)")}
    return p,st,nil
}
func digestExecutable(path string)(string,error){
    f,err:=os.Open(path);if err!=nil{return "",err}
    defer f.Close()
    h:=sha256.New()
    n,err:=io.Copy(h,io.LimitReader(f,maxReviewExecutableSize+1))
    if err!=nil{return "",err}
    if n>maxReviewExecutableSize{return "",errors.New("reviewed program exceeded size limit")}
    return hex.EncodeToString(h.Sum(nil)),nil
}
func (s *Server) beginLaunchReview(path string)(LaunchReview,error){
    if s.active==nil||!s.active.launchReviewOn(){return LaunchReview{},errors.New("enable live protection and the separate Scan & Run toggle first")}
    clean,st,err:=reviewedExecutable(path)
    if err!=nil {
        s.active.recordLaunch(path,"launch-refused",err.Error(),0)
        return LaunchReview{},err
    }
    digest,err:=digestExecutable(clean);if err!=nil{return LaunchReview{},err}
    metaSig,publisher:=v42VerifySignature(clean)
    zone,internetZone,zoneErr:=v42ZoneIdentifier(clean)
    if zoneErr!=nil {zone="Zone.Identifier could not be read; provenance unverified"}
    // Timeout is a fail-closed decision. The scanner may continue its
    // bounded read internally, but no launch ticket is produced on failure.
    type outcome struct{ finding *Finding; errors []string }
    done:=make(chan outcome,1)
    go func(){
        var reasons []string
        finding:=inspectFileProtected(clean,st,func(reason string){reasons=append(reasons,reason)})
        done<-outcome{finding,reasons}
    }()
    var scan outcome
    select{
    case scan=<-done:
    case <-time.After(8*time.Second):
        s.active.recordLaunch(clean,"launch-refused","Static inspection timed out; no approval ticket issued",0)
        return LaunchReview{},errors.New("inspection timed out: could not inspect executable; launch denied")
    }
    if len(scan.errors)>0{
        s.active.recordLaunch(clean,"launch-refused","Static inspection incomplete: "+strings.Join(scan.errors,"; "),0)
        return LaunchReview{},errors.New("could not fully inspect executable: "+strings.Join(scan.errors,"; "))
    }
    f:=scan.finding
    result:=LaunchReview{Path:clean,Score:0,Severity:"No finding",ExpiresAt:time.Now().Add(90*time.Second),
        SHA256:digest,Size:st.Size(),Authenticode:metaSig,Publisher:publisher,Zone:zone,InternetZone:internetZone,
        Inspection:"No indicators found by SentinelGuard (not a safety guarantee)",
        Warning:"Windows Shell will retain applicable download security prompts. Static scanning cannot prove a program safe. Scan & Run does not intercept other Windows launches."}
    if f!=nil {result.Score=f.Score;result.Severity=f.Severity;result.Reasons=append([]string{},f.Reasons...);result.Inspection="Indicators found — review required"}
    secret:=make([]byte,24)
    if _,err:=rand.Read(secret);err!=nil{return LaunchReview{},err}
    result.Ticket=base64.RawURLEncoding.EncodeToString(secret)
    s.launchMu.Lock()
    if s.launchTickets==nil{s.launchTickets=make(map[string]launchTicket)}
    // Limit memory if the user repeatedly opens reviews and never approves.
    for k,v:=range s.launchTickets {if time.Now().After(v.Expires){delete(s.launchTickets,k)}}
    if len(s.launchTickets)>=32{
        s.launchMu.Unlock()
        return LaunchReview{},errors.New("too many outstanding launch reviews; close old prompts")
    }
    s.launchTickets[result.Ticket]=launchTicket{Path:clean,Digest:digest,Size:st.Size(),Expires:result.ExpiresAt,Score:result.Score,Signature:metaSig,Publisher:publisher,Zone:zone,InternetZone:internetZone}
    s.launchMu.Unlock()
    s.active.recordLaunchDigest(clean,"launch-reviewed","SHA-256 checked; Windows Shell approval required",result.Score,digest)
    return result,nil
}
func (s *Server) decideLaunch(ticket string,approve bool)error{
    if s.active==nil||!s.active.launchReviewOn(){return errors.New("live protection or Scan & Run is disabled")}
    s.launchMu.Lock()
    entry,ok:=s.launchTickets[ticket]
    if ok {delete(s.launchTickets,ticket)}
    s.launchMu.Unlock()
    if !ok {return errors.New("missing, expired, or already-used review ticket")}
    if !approve {
        s.active.recordLaunchDigest(entry.Path,"launch-cancelled","User declined the Scan & Run launch",entry.Score,entry.Digest)
        return nil
    }
    if time.Now().After(entry.Expires){
        s.active.recordLaunch(entry.Path,"launch-denied","Review expired before approval",entry.Score)
        return errors.New("review expired; scan the executable again")
    }
    clean,st,err:=reviewedExecutable(entry.Path)
    if err!=nil {
        s.active.recordLaunch(entry.Path,"launch-denied","File disappeared or became ineligible",entry.Score)
        return err
    }
    if clean!=entry.Path||st.Size()!=entry.Size{
        s.active.recordLaunch(entry.Path,"launch-denied","File size/path changed after review",entry.Score)
        return errors.New("executable changed since review; scan again")
    }
    digest,err:=digestExecutable(entry.Path)
    if err!=nil||subtle.ConstantTimeCompare([]byte(digest),[]byte(entry.Digest))!=1{
        s.active.recordLaunch(entry.Path,"launch-denied","SHA-256 changed since review",entry.Score)
        return errors.New("executable changed since review; scan again")
    }
    launcher:=s.launchRunner
    if launcher==nil{launcher=func(p string)error{return secureLaunchReviewedExecutable(p,entry.Digest,entry.Size)}}
    if err:=launcher(entry.Path);err!=nil{
        s.active.recordLaunch(entry.Path,"launch-failed",fmt.Sprintf("Windows refused to start executable: %v",err),entry.Score)
        return err
    }
    s.active.recordLaunchDigest(entry.Path,"launch-approved","User approved Scan & Run after static inspection; Windows Shell invoked",entry.Score,entry.Digest)
    return nil
}
func registerLaunchRoutes(mux *http.ServeMux,s *Server){
    if s.active==nil{return}
    mux.HandleFunc("/api/active/launch-choose",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        if !s.active.launchReviewOn(){apiError(w,409,errors.New("enable live protection and Scan & Run first"));return}
        if !s.pickingFolder.CompareAndSwap(false,true){apiError(w,409,errors.New("a file/folder picker is already open"));return}
        defer s.pickingFolder.Store(false)
        path,err:=chooseScanExecutable()
        if errors.Is(err,errFolderPickerCanceled){sendJSON(w,map[string]any{"cancelled":true});return}
        if err!=nil{apiError(w,500,err);return}
        review,err:=s.beginLaunchReview(path)
        if err!=nil{apiError(w,400,err);return}
        sendJSON(w,review)
    })
    mux.HandleFunc("/api/active/launch-decision",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{ Ticket string; Approve bool }
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        if err:=s.decideLaunch(req.Ticket,req.Approve);err!=nil{apiError(w,409,err);return}
        sendJSON(w,map[string]any{"ok":true,"approved":req.Approve})
    })
}
