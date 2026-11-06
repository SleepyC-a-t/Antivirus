package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
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

type Status struct {
	Active   bool      `json:"active"`
	Mode     string    `json:"mode"`
	Current  string    `json:"current"`
	Files    int64     `json:"files"`
	Skipped  int64     `json:"skipped"`
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
	a.status = Status{Active: true, Mode: mode, Started: time.Now()}
	a.cancel = cancel
	return ctx, nil
}
func (a *App) finish(err error) {
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
func (a *App) incrSkipped()        { atomic.AddInt64(&a.skipped, 1) }
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

// Walk without following links, reparse-point junctions, or other redirected directories.
func walkNoLinks(ctx context.Context, root string, emit func(string)) (int64, error) {
	stat, err := os.Lstat(root)
	if err != nil {
		return 1, err
	}
	if (stat.Mode()&os.ModeSymlink) != 0 || isReparse(root) {
		return 1, nil
	}
	if !stat.IsDir() {
		emit(root)
		return 0, nil
	}
	stack := []string{root}
	var skipped int64
	for len(stack) > 0 {
		if ctx.Err() != nil {
			return skipped, ctx.Err()
		}
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := os.ReadDir(dir)
		if err != nil {
			skipped++
			continue
		}
		for _, ent := range entries {
			if ctx.Err() != nil {
				return skipped, ctx.Err()
			}
			p := filepath.Join(dir, ent.Name())
			if (ent.Type()&os.ModeSymlink) != 0 || isReparse(p) {
				skipped++
				continue
			}
			if ent.IsDir() {
				if shouldSkipDir(p) {
					skipped++
					continue
				}
				stack = append(stack, p)
			} else if ent.Type().IsRegular() || ent.Type() == 0 {
				emit(p)
			}
		}
	}
	return skipped, nil
}

func shouldSkipDir(p string) bool {
	lower := strings.ToLower(filepath.Base(p))
	// Quarantined content must not be examined or handled by the scanner.
	if lower == "sentinellite" {
		return true
	}
	return false
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
	var wg sync.WaitGroup
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					continue
				}
				info, err := os.Lstat(p)
				if err != nil || !info.Mode().IsRegular() {
					a.incrSkipped()
					continue
				}
				a.incrFiles()
				f := inspectFile(p, info)
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
		skipped, e := walkNoLinks(ctx, root, func(p string) {
			select {
			case jobs <- p:
			case <-ctx.Done():
			}
		})
		atomic.AddInt64(&a.skipped, skipped)
		if e != nil {
			aborted = e
			break
		}
	}
	close(jobs)
	wg.Wait()
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
var eicar = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

func inspectFile(p string, info os.FileInfo) *Finding {
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
		} else {
			add(45, "Resembles a Windows system-process filename outside a system directory; may be a harmless renamed file")
		}
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

	inspectContent := isThreatScriptExtension(ext) || ext==".html" || ext==".htm" || ext==".sys" || scriptExtensions[ext] || executableExtensions[ext] || isDocumentOrImage(ext) || ext == ".lnk" || isZIPContainer(ext) || riskExtensions[ext] || stage9InspectableExtension(ext) || score > 0
	if inspectContent {
		if isZIPContainer(ext) && info.Size() <= 64*1024*1024 {
			inspectZIP(p, &score, &reasons)
		}
		// Do not read all huge files: sample only small file heads.
		maxRead := int64(4096)
		if isThreatScriptExtension(ext) || ext==".html" || ext==".htm" {
			maxRead = 2 * 1024 * 1024
		}
		if stage9InspectableExtension(ext) {
			maxRead = 512 * 1024
		}
		if info.Size() <= 32*1024*1024 && maxRead > info.Size() {
			maxRead = info.Size()
		}
		if info.Size() > 0 && maxRead > 0 {
			fh, err := os.Open(p)
			if err == nil {
				buf, _ := io.ReadAll(io.LimitReader(fh, maxRead))
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
				}
				if isDocumentOrImage(ext) && isPEHeader(buf) {
					add(80, "Valid PE executable header disguised as a document or image")
				}
				inspectPEFileMetadata(buf, ext, &score, &reasons)
				inspectStage9Content(name, ext, buf, &score, &reasons)
				_ = fh.Close()
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
	if info.Size()>2*1024*1024*1024 {
		f.CanQuarantine=false
		f.Reasons=append(f.Reasons,"Quarantine unavailable: file exceeds 2 GiB limit")
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
	windir:=strings.ToLower(filepath.Clean(os.Getenv("WINDIR")))
	if windir=="." {windir=`c:\windows`}
	clean:=strings.ToLower(filepath.Clean(lower))
	return strings.HasPrefix(clean,strings.ToLower(filepath.Join(windir,"winsxs"))+string(os.PathSeparator))
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
