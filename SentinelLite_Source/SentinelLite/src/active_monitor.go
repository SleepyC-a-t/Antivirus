package main

import (
    "context"
    "errors"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

// Active is an opt-in, user-mode *near-real-time* download monitor.
// It does not intercept kernel file writes, browser HTTPS traffic, or execution.
// Windows Defender should remain enabled as the primary real-time antivirus.
const activeMaxEntries=30000
const activeMaxFileSize=256*1024*1024

type activeStamp struct { size int64; modified int64 }
type activePending struct { stamp activeStamp; observations int }
type ActiveEvent struct {
    At time.Time `json:"at"`
    Path string `json:"path"`
    Action string `json:"action"`
    Score int `json:"score"`
    Reason string `json:"reason"`
}
type ActiveStatus struct {
    Edition string `json:"edition"`
    Enabled bool `json:"enabled"`
    AutoQuarantine bool `json:"autoQuarantine"`
    WatchedFolders []string `json:"watchedFolders"`
    Inspected int64 `json:"inspected"`
    Flagged int64 `json:"flagged"`
    Quarantined int64 `json:"quarantined"`
    LastError string `json:"lastError,omitempty"`
    Events []ActiveEvent `json:"events"`
    WatcherMode string `json:"watcherMode"`
    LaunchReviewEnabled bool `json:"launchReviewEnabled"`
    LaunchReviews int64 `json:"launchReviews"`
    LaunchAllowed int64 `json:"launchAllowed"`
    LaunchDenied int64 `json:"launchDenied"`
    Notice string `json:"notice"`
}
type ActiveMonitor struct {
    mu sync.RWMutex
    enabled bool
    autoQuarantine bool
    launchReviewEnabled bool
    launchReviews,launchAllowed,launchDenied int64
    wake chan struct{}
    stopWatch context.CancelFunc
    watched []string
    seen map[string]activeStamp
    pending map[string]activePending
    events []ActiveEvent
    inspected,flagged,quarantined int64
    lastError string
    vault *Vault
    inspect func(string,os.FileInfo)*Finding
}
func newActiveMonitor(vault *Vault) *ActiveMonitor {
    home,_:=os.UserHomeDir()
    folders:=[]string{}
    downloads:=filepath.Join(home,"Downloads")
    if stat,err:=os.Lstat(downloads);err==nil&&stat.IsDir()&&!isReparse(downloads) {
        folders=append(folders,downloads)
    }
    return &ActiveMonitor{watched:folders,seen:make(map[string]activeStamp),pending:make(map[string]activePending),wake:make(chan struct{},1),vault:vault,autoQuarantine:false,inspect:func(p string,st os.FileInfo)*Finding{return inspectFileProtected(p,st,nil)}}
}
func (a *ActiveMonitor) snapshot() ActiveStatus {
    a.mu.RLock();defer a.mu.RUnlock()
    out:=ActiveStatus{Edition:"SentinelGuard 4.1",Enabled:a.enabled,AutoQuarantine:a.autoQuarantine,LaunchReviewEnabled:a.launchReviewEnabled,WatcherMode:activeNativeWatcherMode(),LaunchReviews:a.launchReviews,LaunchAllowed:a.launchAllowed,LaunchDenied:a.launchDenied,
        WatchedFolders:append([]string{},a.watched...),Inspected:a.inspected,Flagged:a.flagged,
        Quarantined:a.quarantined,LastError:a.lastError,Events:append([]ActiveEvent{},a.events...),
        Notice:"Opt-in user-mode monitoring; Windows filesystem change notifications with periodic reconciliation. Files are inspected after writes settle, not before execution. Scan & Run is an optional pre-launch review only when the user explicitly launches from SentinelGuard, not a system-wide executable blocker. Keep your main antivirus enabled."}
    return out
}
func (a *ActiveMonitor) appendEventLocked(e ActiveEvent) {
    if len(a.events)>=250 {copy(a.events,a.events[1:]);a.events[len(a.events)-1]=e
    } else {a.events=append(a.events,e)}
}
func (a *ActiveMonitor) setLaunchReview(value bool){
    a.mu.Lock()
    a.launchReviewEnabled=value
    a.appendEventLocked(ActiveEvent{At:time.Now(),Action:map[bool]string{true:"launch-review-enabled",false:"launch-review-disabled"}[value],Reason:"User changed opt-in Scan & Run setting"})
    a.mu.Unlock()
}
func (a *ActiveMonitor) recordLaunch(path,action,reason string,score int){
    a.mu.Lock()
    a.appendEventLocked(ActiveEvent{At:time.Now(),Path:path,Action:action,Reason:reason,Score:score})
    if action=="launch-reviewed"{a.launchReviews++}
    if action=="launch-approved"{a.launchAllowed++}
    if action=="launch-denied"||action=="launch-cancelled"{a.launchDenied++}
    a.mu.Unlock()
}
func (a *ActiveMonitor) launchReviewOn()bool{
    a.mu.RLock();defer a.mu.RUnlock()
    return a.enabled&&a.launchReviewEnabled
}
func (a *ActiveMonitor) setAutoQuarantine(value bool) {
    a.mu.Lock();a.autoQuarantine=value;a.mu.Unlock()
}
func verifyWatchFolder(path string)(string,error) {
    if strings.TrimSpace(path)=="" {return "",errors.New("select a folder to monitor")}
    abs,err:=filepath.Abs(filepath.Clean(path));if err!=nil{return "",err}
    st,err:=os.Lstat(abs);if err!=nil{return "",err}
    if !st.IsDir()||st.Mode()&os.ModeSymlink!=0||isReparse(abs) {return "",errors.New("watch target must be a real directory (no links or reparse points)")}
    return abs,nil
}
func (a *ActiveMonitor) addFolder(path string) error {
    normalized,err:=verifyWatchFolder(path);if err!=nil{return err}
    a.mu.Lock()
    for _,p:=range a.watched {if strings.EqualFold(p,normalized){a.mu.Unlock();return nil}}
    if len(a.watched)>=8 {a.mu.Unlock();return errors.New("at most eight folders may be monitored")}
    a.watched=append(a.watched,normalized)
    enabled:=a.enabled
    a.mu.Unlock()
    if enabled {
        // Avoid treating the folder's previous contents as new downloads.
        baseline,_:=collectActiveFiles([]string{normalized})
        a.mu.Lock()
        for p,stamp:=range baseline {a.seen[p]=stamp}
        a.mu.Unlock()
    }
    if enabled {a.restartNativeWatchers()}
    return nil
}
func (a *ActiveMonitor) removeFolder(path string) error {
    a.mu.Lock();defer a.mu.Unlock()
    for i,p:=range a.watched {
        if strings.EqualFold(filepath.Clean(p),filepath.Clean(path)){
            a.watched=append(a.watched[:i],a.watched[i+1:]...)
            go a.restartNativeWatchers()
            return nil
        }
    }
    return errors.New("folder not in watch list")
}
func (a *ActiveMonitor) setEnabled(enabled bool) error {
    a.mu.RLock()
    old:=a.enabled
    roots:=append([]string{},a.watched...)
    a.mu.RUnlock()
    if enabled && len(roots)==0 {return errors.New("add a folder first; no Downloads folder was found")}
    if old==enabled {return nil}
    // Baseline the files already present to avoid blocking unrelated installed
    // software. A new file/changed file will be checked on subsequent polls.
    baseline:=map[string]activeStamp{}
    truncated:=false
    if enabled {baseline,truncated=collectActiveFiles(roots)}
    a.mu.Lock()
    if enabled {
        a.seen=baseline
        a.pending=make(map[string]activePending)
        if truncated {a.lastError="Watch enumeration reached the 30,000-file safety limit; some subfolders are not watched."}else{a.lastError=""}
    }
    a.enabled=enabled
    a.appendEventLocked(ActiveEvent{At:time.Now(),Action:map[bool]string{true:"enabled",false:"disabled"}[enabled],Reason:"User toggled live protection"})
    a.mu.Unlock()
    a.restartNativeWatchers()
    return nil
}
func activeStampOf(info os.FileInfo) activeStamp {return activeStamp{info.Size(),info.ModTime().UnixNano()}}
func isCompletedDownloadCandidate(path string, st os.FileInfo) bool {
    if st==nil||!st.Mode().IsRegular()||isReparse(path)||st.Size()==0||st.Size()>activeMaxFileSize {return false}
    low:=strings.ToLower(filepath.Base(path))
    for _,s:=range []string{".part",".crdownload",".tmp",".download",".partial"} {
        if strings.HasSuffix(low,s) {return false}
    }
    return true
}
func collectActiveFiles(roots []string)(map[string]activeStamp,bool){
    found:=make(map[string]activeStamp)
    count:=0;truncated:=false
    for _,root:=range roots {
        if truncated {break}
        _=filepath.WalkDir(root,func(p string,d os.DirEntry,err error)error {
            if err!=nil {return nil}
            count++
            if count>activeMaxEntries {truncated=true;return filepath.SkipAll}
            if d.IsDir() {
                if (p!=root&&isReparse(p))||shouldSkipDir(p){return filepath.SkipDir}
                return nil
            }
            if d.Type()&os.ModeSymlink!=0||isReparse(p){return nil}
            info,err:=d.Info();if err!=nil||!isCompletedDownloadCandidate(p,info){return nil}
            found[p]=activeStampOf(info)
            return nil
        })
    }
    return found,truncated
}
func (a *ActiveMonitor) pollOnce() {
    a.mu.RLock()
    enabled:=a.enabled
    roots:=append([]string{},a.watched...)
    a.mu.RUnlock()
    if !enabled {return}
    current,truncated:=collectActiveFiles(roots)
    candidates:=make([]string,0,20)
    now:=time.Now()
    a.mu.Lock()
    if !a.enabled {a.mu.Unlock();return}
    if truncated {a.lastError="Watch enumeration exceeded the 30,000-file limit. Reduce monitored folder size."}
    for p,stamp:=range current {
        if prior,ok:=a.seen[p];ok&&prior==stamp {delete(a.pending,p);continue}
        pending,exists:=a.pending[p]
        if !exists||pending.stamp!=stamp {
            a.pending[p]=activePending{stamp:stamp,observations:1}
            continue
        }
        pending.observations++
        a.pending[p]=pending
        if pending.observations<2 {continue}
        // Reduce false alarms from partially written files.
        if now.Sub(time.Unix(0,stamp.modified))<2*time.Second{continue}
        a.seen[p]=stamp
        delete(a.pending,p)
        if len(candidates)<64 {candidates=append(candidates,p)}
    }
    for p:=range a.pending {if _,exists:=current[p];!exists{delete(a.pending,p)}}
    a.mu.Unlock()
    for _,p:=range candidates {
        a.mu.RLock();stillOn:=a.enabled;a.mu.RUnlock()
        if !stillOn{return}
        st,err:=os.Lstat(p)
        if err!=nil||!isCompletedDownloadCandidate(p,st) {continue}
        if activeStampOf(st)!=current[p] {continue}
        f:=a.inspect(p,st)
        a.mu.Lock();a.inspected++;autoBlock:=a.autoQuarantine
        if f==nil {
            a.appendEventLocked(ActiveEvent{At:time.Now(),Path:p,Action:"inspected-clean",Reason:"Static review found no high-confidence indicators; not a guarantee of safety"})
        }
        a.mu.Unlock()
        if f==nil {continue}
        action:="flagged"
        reason:=strings.Join(f.Reasons,"; ")
        if autoBlock && f.Score>=110 && f.CanQuarantine && a.vault!=nil {
            if _,err:=a.vault.quarantine(*f);err==nil {
                action="quarantined"
            }else{
                action="quarantine-failed"
                reason+="; quarantine failed: "+err.Error()
            }
        }
        a.mu.Lock()
        a.flagged++
        if action=="quarantined" {a.quarantined++}
        a.appendEventLocked(ActiveEvent{At:time.Now(),Path:p,Action:action,Score:f.Score,Reason:reason})
        a.mu.Unlock()
    }
}
// The platform notifier signals changes; periodic reconciliation catches
// missed notifications, watcher failures, and FAT/network drive differences.
func (a *ActiveMonitor) restartNativeWatchers(){
    a.mu.Lock()
    if a.stopWatch!=nil {a.stopWatch();a.stopWatch=nil}
    if !a.enabled {a.mu.Unlock();return}
    roots:=append([]string{},a.watched...)
    ctx,cancel:=context.WithCancel(context.Background())
    a.stopWatch=cancel
    a.mu.Unlock()
    for _,root:=range roots {
        go watchActiveDirectory(ctx,root,a.wake)
    }
}
func (a *ActiveMonitor) start() {
    go func(){
        periodic:=time.NewTicker(activeReconcileInterval())
        defer periodic.Stop()
        // Coalesce notifications; always re-check file stability before
        // accessing potentially incomplete browser downloads.
        timer:=time.NewTimer(time.Hour)
        if !timer.Stop(){select{case <-timer.C:default:}}
        defer timer.Stop()
        retry:=time.NewTimer(time.Hour)
        if !retry.Stop(){select{case <-retry.C:default:}}
        defer retry.Stop()
        run:=func(){
            defer func(){if x:=recover();x!=nil{
                log.Printf("active watcher error: %v",x)
                a.mu.Lock();a.lastError="Watcher internal error; see diagnostics log";a.mu.Unlock()
            }}()
            a.pollOnce()
        }
        for {
            select{
            case <-a.wake:
                if !timer.Stop(){select{case <-timer.C:default:}}
                timer.Reset(750*time.Millisecond)
            case <-timer.C:
                run()
                if !retry.Stop(){select{case <-retry.C:default:}}
                retry.Reset(3*time.Second)
            case <-retry.C:
                run()
            case <-periodic.C:
                run()
            }
        }
    }()
}
func (a *ActiveMonitor) clearHistory(){
    a.mu.Lock();a.events=nil;a.inspected=0;a.flagged=0;a.quarantined=0;a.mu.Unlock()
}
func (a *ActiveMonitor) summaryText() string {
    s:=a.snapshot()
    return fmt.Sprintf("enabled=%t inspected=%d flagged=%d quarantined=%d",s.Enabled,s.Inspected,s.Flagged,s.Quarantined)
}
