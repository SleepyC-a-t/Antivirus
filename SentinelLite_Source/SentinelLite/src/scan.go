package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Finding struct {
	ID            string    `json:"id"`
	Path          string    `json:"path"`
	Name          string    `json:"name"`
	Score         int       `json:"score"`
	Severity      string    `json:"severity"`
	Source        string    `json:"source"`
	Reasons       []string  `json:"reasons"`
	Size          int64     `json:"size"`
	Modified      time.Time `json:"modified"`
	CanQuarantine bool      `json:"canQuarantine"`
	ReviewSHA256 string `json:"-"`
}

type SkippedPath struct {
	Path string `json:"path"`
	Reason string `json:"reason"`
}

// A practical safety ceiling for pathological filesystems; any excess is
// explicitly counted in status.skipLogOmitted, not silently discarded.
const maxSkippedPathRecords = 100000

type Status struct {
	Active   bool      `json:"active"`
	Mode     string    `json:"mode"`
	Current  string    `json:"current"`
	Files    int64     `json:"files"`
	Skipped  int64     `json:"skipped"`
    Resources ScanResourceUsage `json:"resources"`
	SkipLogOmitted int64 `json:"skipLogOmitted"`
	Findings int       `json:"findings"`
	Omitted int64 `json:"omitted"`
	Started  time.Time `json:"started"`
	Error    string    `json:"error"`
}

type App struct {
	mu         sync.RWMutex
	findings   map[string]Finding
	order      []string
	status     Status
	cancel     context.CancelFunc
	quarantine *Vault
	busy       bool
	files      int64
	skipped    int64
	skippedPaths []SkippedPath
	skipLogOmitted int64
    resources ScanResourceUsage
    resourceDone chan struct{}
    lastResourceCPU float64
    lastResourceAt time.Time
    sumCPUPercent float64
    sumMemoryMiB float64
    cpuObservations int64
    memObservations int64
	omitted int64
}

func newApp(v *Vault) *App {
	return &App{findings: make(map[string]Finding), quarantine: v}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (a *App) add(f Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.findings) >= 3000 {
		atomic.AddInt64(&a.omitted,1)
		return
	}
	f.ID = newID()
	a.findings[f.ID] = f
	a.order = append(a.order, f.ID)
	a.status.Findings = len(a.findings)
}

func (a *App) snapshot() (Status, []Finding) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s := a.status
	s.Files = atomic.LoadInt64(&a.files)
	s.Skipped = atomic.LoadInt64(&a.skipped)
	s.Omitted = atomic.LoadInt64(&a.omitted)
	s.SkipLogOmitted = a.skipLogOmitted
    s.Resources = a.resources
	fs := make([]Finding, 0, len(a.order))
	for _, id := range a.order {
		fs = append(fs, a.findings[id])
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Score > fs[j].Score })
	return s, fs
}

func (a *App) begin(mode string) (context.Context, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status.Active || a.busy {
		return nil, errors.New("another operation is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.findings = make(map[string]Finding)
	atomic.StoreInt64(&a.files, 0)
	atomic.StoreInt64(&a.skipped, 0)
	atomic.StoreInt64(&a.omitted, 0)
	a.order = nil
	a.skippedPaths = nil
	a.skipLogOmitted = 0
	a.status = Status{Active: true, Mode: mode, Started: time.Now()}
    a.resetMetricsLocked()
	a.cancel = cancel
	return ctx, nil
}
func (a *App) finish(err error) {
    a.stopResources()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.Active = false
	if err != nil && !errors.Is(err, context.Canceled) {
		a.status.Error = err.Error()
	}
	if errors.Is(err, context.Canceled) {
		a.status.Error = "Scan stopped by user. Results are partial."
	}
	a.cancel = nil
    log.Printf("Scan finished: mode=%s files=%d skipped=%d findings=%d omitted=%d error=%q",a.status.Mode,atomic.LoadInt64(&a.files),atomic.LoadInt64(&a.skipped),a.status.Findings,atomic.LoadInt64(&a.omitted),a.status.Error)
}
func (a *App) stop() {
	a.mu.RLock()
	c := a.cancel
	a.mu.RUnlock()
	if c != nil {
		c()
	}
}
func (a *App) incrFiles()          { atomic.AddInt64(&a.files, 1) }
// Record skipped paths and reasons for the JSON report. The count is always
// complete even if an extreme number of records exhaust the safety cap.
func (a *App) recordSkip(path, reason string) {
    a.mu.Lock()
    defer a.mu.Unlock()
    atomic.AddInt64(&a.skipped, 1)
    if len(a.skippedPaths) < maxSkippedPathRecords {
        a.skippedPaths = append(a.skippedPaths, SkippedPath{Path: path, Reason: reason})
    } else {
        a.skipLogOmitted++
    }
}
func (a *App) skippedSnapshot() []SkippedPath {
    a.mu.RLock()
    defer a.mu.RUnlock()
    return append([]SkippedPath{}, a.skippedPaths...)
}
func (a *App) setCurrent(p string) { a.mu.Lock(); a.status.Current = p; a.mu.Unlock() }

func scanRoots(mode, custom string) ([]string, error) {
	if mode == "custom" {
		if strings.TrimSpace(custom) == "" {
			return nil, errors.New("enter a file or folder path")
		}
		p, err := filepath.Abs(os.ExpandEnv(strings.TrimSpace(strings.Trim(custom, `"`))))
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(p); err != nil {
			return nil, err
		}
		return []string{p}, nil
	}
	if mode == "full" {
		roots := fixedAndRemovableDrives()
		if len(roots) == 0 {
			return nil, errors.New("no local drives found")
		}
		return roots, nil
	}
	if mode != "quick" {
		return nil, errors.New("invalid scan type")
	}
	home, _ := os.UserHomeDir()
	roaming := os.Getenv("APPDATA")
	local := os.Getenv("LOCALAPPDATA")
	programData := os.Getenv("ProgramData")
	roots := []string{
		filepath.Join(home, "Downloads"), filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"), roaming,
		filepath.Join(local, "Temp"), filepath.Join(local, "Programs"),
		filepath.Join(roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
	}
	uniq := map[string]bool{}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		if r == "" || r == "." {
			continue
		}
		r = filepath.Clean(r)
		low := strings.ToLower(r)
		if !uniq[low] {
			if _, err := os.Stat(r); err == nil {
				uniq[low] = true
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no quick-scan folders found")
	}
	return out, nil
}

// Walk without following symbolic links or Windows reparse points. The
// detailed path is used by the scanner; the compatibility wrapper preserves
// the original test/helper API.
func walkNoLinks(ctx context.Context, root string, emit func(string)) (int64, error) {
    return walkNoLinksDetailed(ctx, root, emit, nil)
}
func walkNoLinksDetailed(ctx context.Context, root string, emit func(string), onSkip func(string,string)) (int64,error) {
    var skipped int64
    skip:=func(path,why string) {
        skipped++
        if onSkip!=nil { onSkip(path,why) }
    }
    stat,err:=os.Lstat(root)
    if err!=nil { skip(root,"metadata access failed: "+err.Error());return skipped,err }
    if stat.Mode()&os.ModeSymlink!=0 || isReparse(root) {
        skip(root,"symbolic link or reparse point: not followed for safety")
        return skipped,nil
    }
    if !stat.IsDir() {
        if !stat.Mode().IsRegular() {skip(root,"not a regular file");return skipped,nil}
        emit(root);return skipped,nil
    }
    stack:=[]string{root}
    for len(stack)>0 {
        if ctx.Err()!=nil{return skipped,ctx.Err()}
        dir:=stack[len(stack)-1]
        stack=stack[:len(stack)-1]
        entries,err:=os.ReadDir(dir)
        if err!=nil && !errors.Is(err,os.ErrPermission) {
            // One bounded retry helps with short-lived sharing violations.
            time.Sleep(20*time.Millisecond)
            entries,err=os.ReadDir(dir)
        }
        if err!=nil {skip(dir,"directory listing failed: "+err.Error());continue}
        for _,ent:=range entries {
            if ctx.Err()!=nil{return skipped,ctx.Err()}
            p:=filepath.Join(dir,ent.Name())
            if ent.Type()&os.ModeSymlink!=0 || isReparse(p) {
                skip(p,"symbolic link or reparse point: not followed for safety")
                continue
            }
            if ent.IsDir() {
                if shouldSkipDir(p) {
                    skip(p,"SentinelGuard quarantine directory: intentionally excluded")
                    continue
                }
                stack=append(stack,p)
            } else if ent.Type().IsRegular() || ent.Type()==0 {
                emit(p)
            } else {
                skip(p,"not a regular file (device, socket, or special entry)")
            }
        }
    }
    return skipped,nil
}

// Exclude only our own quarantine storage, not every unrelated folder named
// SentinelLite. The old basename-only exclusion silently missed whole trees.
func shouldSkipDir(p string) bool {
    config:=os.Getenv("LOCALAPPDATA")
    if config=="" { config,_=os.UserConfigDir() }
    if config=="" {return false}
    return strings.EqualFold(filepath.Clean(p),filepath.Clean(filepath.Join(config,"SentinelLite")))
}

func (a *App) runHeuristic(ctx context.Context, mode, custom string) error {
	roots, err := scanRoots(mode, custom)
	if err != nil {
		return err
	}
	limit := runtime.NumCPU()
	if limit > 4 {
		limit = 4
	}
	if limit < 1 {
		limit = 1
	}
	jobs := make(chan string, 128)
    workerFailures:=make(chan string,limit)
	var wg sync.WaitGroup
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
            defer func(){
                if incident:=recover();incident!=nil {
                    log.Printf("scanner worker error: %v",incident)
                    select{case workerFailures<-fmt.Sprint("scanner worker failure; see local diagnostics log"):default:}
                }
            }()
			for p := range jobs {
				if ctx.Err() != nil {
					continue
				}
				info, err := os.Lstat(p)
				if err != nil {
                    a.recordSkip(p,"file metadata failed: "+err.Error())
                    continue
                }
                if !info.Mode().IsRegular() || isReparse(p) {
                    a.recordSkip(p,"not a regular file or changed to a reparse point")
                    continue
                }
                a.incrFiles()
                f := inspectFileProtected(p, info, func(reason string) {
                    a.recordSkip(p,reason)
                })
				if f != nil {
					a.add(*f)
				}
			}
		}()
	}
	seen := make(map[string]struct{})
	var aborted error
	for _, root := range roots {
		if ctx.Err() != nil {
			aborted = ctx.Err()
			break
		}
		a.setCurrent(root)
		_, ok := seen[strings.ToLower(root)]
		if ok {
			continue
		}
		seen[strings.ToLower(root)] = struct{}{}
		_, e := walkNoLinksDetailed(ctx, root, func(p string) {
			select {
			case jobs <- p:
			case <-ctx.Done():
			}
		}, a.recordSkip)
		if e != nil {
			aborted = e
			break
		}
	}
	close(jobs)
	wg.Wait()
    close(workerFailures)
    if len(workerFailures)>0 {return errors.New(<-workerFailures)}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return aborted
}

var doubleExt = regexp.MustCompile(`(?i)\.(pdf|jpg|jpeg|png|gif|doc|docx|xls|xlsx|txt|mp3|mp4|zip)\.(exe|com|scr|pif|js|jse|vbs|vbe|hta|bat|cmd|ps1)$`)
var scriptExtensions = map[string]bool{".ps1": true, ".psm1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".bat": true, ".cmd": true, ".wsf": true, ".hta": true}
var executableExtensions = map[string]bool{".exe": true, ".com": true, ".scr": true, ".pif": true, ".dll": true, ".cpl": true, ".msi": true}
var riskExtensions = map[string]bool{".lnk": true, ".jar": true, ".iso": true, ".img": true, ".zip": true, ".7z": true, ".rar": true}
var windowsSystemNames = map[string]bool{"svchost.exe": true, "lsass.exe": true, "csrss.exe": true, "winlogon.exe": true, "services.exe": true, "smss.exe": true, "taskhostw.exe": true, "spoolsv.exe": true, "conhost.exe": true}
var encodedCommandPattern = regexp.MustCompile(`(?i)(?:powershell(?:\.exe)?\s+[^\r\n]{0,120})-(?:encodedcommand|enc|en|e)\s+[a-z0-9+/=]{28,}`)
var executeScriptPattern = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b`)
var pipeInterpreterPattern = regexp.MustCompile(`(?i)\b(?:curl(?:\.exe)?|wget(?:\.exe)?)\s+[^\r\n|]{0,500}https?://[^\s|]+[^\r\n]{0,200}\|\s*(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?)\b`)

func inspectFile(p string, info os.FileInfo) *Finding {
    return inspectFileDetailed(p, info, nil)
}
func inspectFileDetailed(p string, info os.FileInfo, onReadError func(string)) *Finding {
	name := filepath.Base(p)
	ext := strings.ToLower(filepath.Ext(name))
	lower := strings.ToLower(p)
	base := strings.ToLower(name)
	score := 0
	reasons := []string{}
	add := func(points int, reason string) { score += points; reasons = append(reasons, reason) }
	userWritable := strings.Contains(lower, `\appdata\`) || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `/tmp/`)
	startup := strings.Contains(lower, `\start menu\programs\startup\`) || strings.Contains(lower, `\startmenu\startup\`)
	temp := strings.Contains(lower, `\temp\`) || strings.Contains(lower, `/tmp/`)
	if hasMisleadingBidiControls(name) {
		add(80, "Filename contains bidirectional override/control characters that can disguise its extension")
	}
	if doubleExt.MatchString(name) {
		add(80, "Disguised double extension (for example document.pdf.exe)")
	}
	if windowsSystemNames[base] && !isLegitimateSystemPath(lower) && !isWindowsComponentStorePath(lower) {
		if info.Size() >= 512 && hasPEFileSignature(p) {
			add(65, "Windows system-process filename outside a system directory (file has PE signature)")
		} // Mere filename resemblance without a PE header is not enough.
	}
	if startup && (executableExtensions[ext] || scriptExtensions[ext]) {
		add(55, "Executable or script located in a Windows Startup folder")
	}
	if startup && ext == ".lnk" {
		add(25, "Startup shortcut (common for legitimate programs; review only)")
	}
	if temp && executableExtensions[ext] {
		add(23, "Executable in a temporary folder")
	}
	if userWritable && (ext == ".scr" || ext == ".pif" || ext == ".hta" || ext == ".jse" || ext == ".vbe") {
		add(34, "Uncommon executable/script type in a user-writable location")
	}
	if strings.Contains(lower, `\appdata\roaming\`) && (ext == ".exe" || ext == ".dll") {
		add(22, "Executable or library within roaming application data (can be legitimate)")
	}

	inspectContent := isThreatScriptExtension(ext) || ext==".html" || ext==".htm" || ext==".sys" || scriptExtensions[ext] || executableExtensions[ext] || isDocumentOrImage(ext) || ext == ".lnk" || isZIPContainer(ext) || riskExtensions[ext] || stage9InspectableExtension(ext) || stage10InspectableExtension(ext) || stage11InspectableExtension(ext) || stage12InspectableExtension(ext) || score > 0
	if inspectContent {
		if isZIPContainer(ext) {
            if info.Size() <= 512*1024*1024 {
                if err:=inspectZIPWithError(p,&score,&reasons);err!=nil && onReadError!=nil {
                    onReadError("ZIP archive could not be inspected: "+err.Error())
                }
            } else if onReadError!=nil {
                onReadError("ZIP metadata inspection limited to archives at most 512 MiB")
            }
        }
		// Do not read all huge files: sample only small file heads.
		maxRead := int64(4096)
		if isThreatScriptExtension(ext) || ext==".html" || ext==".htm" {
			maxRead = 2 * 1024 * 1024
		}
		if stage9InspectableExtension(ext) || stage10InspectableExtension(ext) || stage11InspectableExtension(ext) || stage12InspectableExtension(ext) {
			maxRead = 512 * 1024
		}
        // Bounded PDF action token review (object streams still not parsed).
        if ext==".pdf"{maxRead=512*1024}
        // Keep the Stage 12 advisory checks cheap on large photo/text libraries.
        // No benefit comes from decoding 512 KiB of every ordinary JPEG.
        switch ext {
        case ".jpg", ".jpeg", ".sys", ".iso":
            maxRead = 4096
        case ".txt":
            maxRead = 64 * 1024
        }
		if ext==".lnk" { maxRead=128*1024 }
        if info.Size() <= 32*1024*1024 && maxRead > info.Size() {
			maxRead = info.Size()
		}
		if info.Size() > 0 && maxRead > 0 {
			fh, err := os.Open(p)
			if err == nil {
				buf, readErr := io.ReadAll(io.LimitReader(fh, maxRead))
                if readErr!=nil && onReadError!=nil {onReadError("content read incomplete: "+readErr.Error())}
				if isExactEICAR(buf) && info.Size() == int64(len(buf)) {
					add(110, "Exact EICAR antivirus test file (harmless standardized test, not malware)")
				}
				if isThreatScriptExtension(ext) || ext==".html" || ext==".htm" || ext == ".txt" || ext == ".7z" || ext==".rar" {
					// Check an additional bounded tail sample for appended script commands.
					if info.Size() > maxRead {
						const tailLimit int64 = 128 * 1024
						if _, err := fh.Seek(-min(info.Size(), tailLimit), io.SeekEnd); err == nil {
							tail, _ := io.ReadAll(io.LimitReader(fh, tailLimit))
							buf = append(buf, '\n')
							buf = append(buf, tail...)
						}
					}
					if isThreatScriptExtension(ext) || ext==".html" || ext==".htm" {
						if scriptExtensions[ext] {inspectScript(buf, &score, &reasons);inspectStage5Patterns(buf, ext, &score, &reasons)}
						inspectThreatBehavior(buf, ext, &score, &reasons)
					} else if ext == ".txt" {
						var scriptScore int
						var scriptReasons []string
						inspectScript(buf, &scriptScore, &scriptReasons)
						lowerText:=strings.ToLower(strings.TrimSpace(decodeScriptText(buf)))
						isDocumentation:=strings.HasPrefix(lowerText,"documentation:") || strings.HasPrefix(lowerText,"example:") || strings.HasPrefix(lowerText,"guide:")
						if scriptScore >= 70 && !isDocumentation {
							add(45, "Text document contains suspicious script-like text; review, not proof of execution")
						}
						inspectRansomNote(name,buf,&score,&reasons)
					} else if ext == ".7z" {
						inspectMisnamed7z(buf, &score, &reasons)
					} else if ext == ".rar" {
						inspectMisnamedRAR(buf, &score, &reasons)
					}
				}
				if ext == ".lnk" {
					inspectValidatedShortcut(buf, &score, &reasons)
                    inspectV42LNK(buf,&score,&reasons)
				}
				if ext==".pdf"{inspectV42PDF(buf,&score,&reasons)}
                if isDocumentOrImage(ext) && isPEHeader(buf) {
					add(80, "Valid PE executable header disguised as a document or image")
				}
				inspectPEFileMetadata(buf, ext, &score, &reasons)
				inspectStage9Content(name, ext, buf, &score, &reasons)
				inspectStage10Content(name, ext, buf, &score, &reasons)
				inspectStage11Content(name, ext, buf, &score, &reasons)
                inspectStage12Content(name, ext, buf, &score, &reasons)
                _ = fh.Close()
                if ext==".exe"||ext==".dll"||ext==".sys"||ext==".scr"||ext==".cpl"{
                    inspectV42PE(p,info,&score,&reasons)
                }
                if (ext==".docm"||ext==".xlsm"||ext==".pptm") && info.Size()<=128*1024*1024{
                    inspectV42MacroPackage(p,ext,&score,&reasons)
                }
            } else if onReadError!=nil {
                onReadError("file content could not be opened: "+err.Error())
            }
		}
	}
	if score < 40 {
		return nil
	}
	severity := "Review"
	if score >= 110 {
		severity = "High"
	} else if score >= 70 {
		severity = "Elevated"
	}
	if score > 150 {
		score = 150
	}
	f:= &Finding{Path: p, Name: name, Score: score, Severity: severity, Source: "Heuristics", Reasons: reasons, Size: info.Size(), Modified: info.ModTime(), CanQuarantine: true}
	if info.Size()>256*1024*1024 {
        f.CanQuarantine=false
        f.Reasons=append(f.Reasons,"Manual review required: files over 256 MiB are not hashed or quarantined by this scanner")
	} else if hash,err:=fileSHA256(p);err==nil {
		f.ReviewSHA256=hash
	} else {
		f.CanQuarantine=false
		f.Reasons=append(f.Reasons,"Cannot verify reviewed file: "+err.Error())
	}
	return f
}

// WinSxS is the legitimate Windows component store. System processes
// regularly appear here as servicing and rollback payloads. Filename-based
// impersonation rules must not flag those copies merely for their location.
// Do not broadly trust application directories: inspect content as usual.
func isWindowsComponentStorePath(lower string) bool {
    // Windows-style path comparison also works in cross-platform unit tests.
    normalize:=func(s string)string{return strings.ToLower(strings.ReplaceAll(s,"/",`\`))}
    windir:=normalize(os.Getenv("WINDIR"))
    if windir==""{windir=`c:\windows`}
    windir=strings.TrimRight(windir,`\`)
    path:=normalize(lower)
    return strings.HasPrefix(path,windir+`\winsxs\`)
}

func isLegitimateSystemPath(lower string) bool {
	windir := strings.ToLower(filepath.Clean(os.Getenv("WINDIR")))
	if windir == "." {
		windir = `c:\windows`
	}
	allowed := []string{filepath.Join(windir, "system32") + string(os.PathSeparator), filepath.Join(windir, "syswow64") + string(os.PathSeparator)}
	for _, prefix := range allowed {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func inspectScript(buf []byte, score *int, reasons *[]string) {
	if len(buf) == 0 {
		return
	}
	raw := strings.ToLower(decodeScriptText(buf))
	if !strings.Contains(raw,"powershell") && !strings.Contains(raw,"download") &&
		!strings.Contains(raw,"invoke-") && !strings.Contains(raw,"frombase64string") &&
		!strings.Contains(raw,"certutil") && !strings.Contains(raw,"schtasks") &&
		!strings.Contains(raw,"regwrite") && !strings.Contains(raw,"reg add") &&
		!strings.Contains(raw,"add-mppreference") && !strings.Contains(raw,"disablerealtimemonitoring") &&
		!strings.Contains(raw,"bitstransfer") && !strings.Contains(raw,"webclient") &&
		!strings.Contains(raw,"encodedcommand") && !strings.Contains(raw,"scriptblock]::create") {
		return
	}
	lower := strings.ToLower(codeOnlyForSignals(raw))
	add := func(n int, desc string) { *score += n; *reasons = append(*reasons, desc) }
	encoded := strings.Contains(lower, "-encodedcommand") || encodedCommandPattern.MatchString(lower)
	if encoded {
		add(52, "PowerShell encoded command or obfuscated execution")
	}
	download := strings.Contains(lower, "downloadstring") || strings.Contains(lower, "downloadfile") || strings.Contains(lower, "downloaddata") || strings.Contains(lower, "invoke-restmethod") || strings.Contains(lower, "invoke-webrequest") || strings.Contains(lower, "new-object net.webclient") || strings.Contains(lower, "start-bitstransfer")
	execute := executeScriptPattern.MatchString(lower) || strings.Contains(lower, "scriptblock]::create")
	if download && execute {
		add(85, "Downloads remote content and directly executes it")
	}
	if pipeInterpreterPattern.MatchString(lower) {
		add(75, "Pipes downloaded network data into a command interpreter")
	}
	if strings.Contains(lower, "frombase64string") && execute {
		add(58, "Decodes Base64 content and executes it")
	}
	if strings.Contains(lower, "-disablerealtimemonitoring") || strings.Contains(lower, "add-mppreference -exclusionpath") {
		add(78, "Attempts to weaken Microsoft Defender protection")
	}
	if strings.Contains(lower, "certutil") && strings.Contains(lower, "-urlcache") {
		add(46, "Uses certutil to retrieve content from a URL")
	}
	if strings.Contains(lower, "schtasks") && strings.Contains(lower, "/create") && (strings.Contains(lower, "powershell") || strings.Contains(lower, "wscript")) {
		add(55, "Creates a scheduled task launching a script interpreter")
	}
	if strings.Contains(lower, "wscript.shell") && strings.Contains(lower, "regwrite") && strings.Contains(lower, `\currentversion\run`) {
		add(70, "Writes persistence into a Windows Run registry key")
	}
	if strings.Contains(lower, "reg add") && strings.Contains(lower, `\currentversion\run`) && strings.Contains(lower, " /d ") {
		add(62, "Adds a Windows Run registry entry (may be legitimate; review the command)")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
