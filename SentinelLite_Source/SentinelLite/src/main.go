package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
    "strings"
    "sync"
	"sync/atomic"
	"time"
)

//go:embed ui.html
var pages embed.FS

// Built separately with -ldflags '-X main.edition=active'. The standard
// SentinelGuard executable retains its existing on-demand behavior.
var edition = "integrated" // v4.1 combines manual and opt-in live scanning

type Server struct {
    active *ActiveMonitor
    extensionToken string // read-only browser companion credential
    pairMu sync.RWMutex
    launchMu sync.Mutex
    launchTickets map[string]launchTicket
    launchRunner func(string) error
    pairPersisted bool
	app     *App
	token   string
	address string
	folderPicker func() (string, error) // optional test override
	pickingFolder atomic.Bool
}

func (s *Server) pairSnapshot()(string,bool) {
 s.pairMu.RLock();defer s.pairMu.RUnlock()
 return s.extensionToken,s.pairPersisted
}
func (s *Server) updatePairToken() error {
 token,err:=rotateProtectedPairingToken()
 if err!=nil{return err}
 s.pairMu.Lock();s.extensionToken=token;s.pairPersisted=true;s.pairMu.Unlock()
 return nil
}
func sendJSON(w http.ResponseWriter, val any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(val)
}
func apiError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	sendJSON(w, map[string]any{"error": err.Error()})
}
func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64*1024)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Preserve the local API's availability if a single request handler
        // panics unexpectedly. Go's default HTTP recovery drops the connection
        // and produces an unhelpful browser NetworkError.
        defer func() {
            if incident := recover(); incident != nil {
                log.Printf("Local API error: %v", panicAsError(incident))
                http.Error(w, "Internal scanner error; inspect local diagnostics log", http.StatusInternalServerError)
            }
        }()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		if r.Host != s.address {
			http.Error(w, "invalid host", 403)
			return
		}
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(remote).IsLoopback() {
			http.Error(w, "local access only", 403)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.address {
            allowExtension := (edition=="integrated"||edition=="active") && (r.URL.Path=="/api/active/extension-status" || r.URL.Path=="/api/active/extension-challenge") &&
                (strings.HasPrefix(o,"moz-extension://") || strings.HasPrefix(o,"chrome-extension://"))
            if !allowExtension {
                http.Error(w,"invalid origin",403);return
            }
            w.Header().Set("Access-Control-Allow-Origin",o)
            w.Header().Set("Vary","Origin")
            w.Header().Set("Access-Control-Allow-Headers","X-Sentinel-Token")
            w.Header().Set("Access-Control-Allow-Methods","GET, POST, OPTIONS")
            if r.Method == http.MethodOptions {w.WriteHeader(http.StatusNoContent);return}
        }
		t := r.Header.Get("X-Sentinel-Token")
		if r.Method == http.MethodGet && t == "" {
			t = r.URL.Query().Get("token")
		}
		authorized:=subtle.ConstantTimeCompare([]byte(t),[]byte(s.token))==1
        if !authorized && r.URL.Path=="/api/active/extension-challenge" && r.Method==http.MethodPost {
            origin:=r.Header.Get("Origin")
            authorized=(strings.HasPrefix(origin,"moz-extension://")||strings.HasPrefix(origin,"chrome-extension://"))
        }
        if !authorized && (edition=="active"||edition=="integrated") && r.URL.Path=="/api/active/extension-status" {
            authorized=func()bool{
                pair,_:=s.pairSnapshot()
                return pair!=""&&subtle.ConstantTimeCompare([]byte(t),[]byte(pair))==1
            }()
        }
        if !authorized {
            http.Error(w,"access token required",403);return
        }
		next.ServeHTTP(w, r)
	})
}
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return false
	}
	return true
}
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "invalid method", 405)
			return
		}
		page, err := pages.ReadFile("ui.html")
		if err != nil {
			http.Error(w, "UI missing", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		status, fs := s.app.snapshot()
		sendJSON(w, map[string]any{"status": status, "findings": fs, "product": map[string]any{"name":"SentinelGuard","version":"4.1", "type":"manual and optional live-protection scanner","activeEdition":s.active!=nil,"desktop":true}})
	})
	mux.HandleFunc("/api/choose-folder", func(w http.ResponseWriter, r *http.Request) {
        if !requirePost(w, r) { return }
        // One native dialog at a time. It is interactive and may remain open
        // while the user navigates Explorer.
        if !s.pickingFolder.CompareAndSwap(false, true) {
            apiError(w, http.StatusConflict, errors.New("a folder picker is already open"))
            return
        }
        defer s.pickingFolder.Store(false)
        s.app.mu.RLock()
        active := s.app.status.Active
        s.app.mu.RUnlock()
        if active {
            apiError(w, http.StatusConflict, errors.New("stop the scan before selecting another folder"))
            return
        }
        picker := chooseScanFolder
        if s.folderPicker != nil { picker = s.folderPicker }
        path, err := picker()
        if errors.Is(err, errFolderPickerCanceled) {
            sendJSON(w, map[string]any{"cancelled": true})
            return
        }
        if err != nil {
            apiError(w, http.StatusInternalServerError, err)
            return
        }
        // Never accept a nonexistent file, a virtual Shell namespace item,
        // or a reparse-point target that the crawler intentionally won't scan.
        info, err := os.Lstat(path)
        if err != nil {
            apiError(w, http.StatusBadRequest, err)
            return
        }
        if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparse(path) {
            apiError(w, http.StatusBadRequest, errors.New("select a regular folder, not a file, symlink or junction"))
            return
        }
        sendJSON(w, map[string]any{"folder": filepath.Clean(path), "cancelled": false})
    })
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		var req struct{ Engine, Mode, Path string }
		if err := readJSON(r, &req); err != nil {
			apiError(w, 400, err)
			return
		}
		if req.Engine != "heuristic" && req.Engine != "defender" {
			apiError(w, 400, errors.New("invalid engine"))
			return
		}
		roots, err := scanRoots(req.Mode, req.Path)
		if err != nil {
			apiError(w, 400, err)
			return
		}
		if len(roots) == 0 {
			apiError(w, 400, errors.New("no targets"))
			return
		}
		if req.Engine == "defender" && defenderEXE() == "" {
			apiError(w, 400, errors.New("Microsoft Defender command-line scanner was not found"))
			return
		}
		ctx, err := s.app.begin(req.Engine + ":" + req.Mode)
		if err != nil {
			apiError(w, 409, err)
			return
		}
		go func() {
			defer func() {
				if failure := recover(); failure != nil {
					s.app.finish(panicAsError(failure))
				}
			}()
			var runErr error
			if req.Engine == "defender" {
				runErr = s.app.runDefender(ctx, req.Mode, req.Path)
			} else {
				runErr = s.app.runHeuristic(ctx, req.Mode, req.Path)
			}
			s.app.finish(runErr)
		}()
		sendJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		s.app.stop()
		sendJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/open", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		var req struct{ ID string }
		if err := readJSON(r, &req); err != nil {
			apiError(w, 400, err)
			return
		}
		s.app.mu.RLock()
		f, ok := s.app.findings[req.ID]
		s.app.mu.RUnlock()
		if !ok || !f.CanQuarantine {
			apiError(w, 404, errors.New("file not accessible"))
			return
		}
		if err := openLocation(f.Path); err != nil {
			apiError(w, 500, err)
			return
		}
		sendJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/hash", func(w http.ResponseWriter, r *http.Request) {
		s.app.mu.RLock()
		f, ok := s.app.findings[r.URL.Query().Get("id")]
		s.app.mu.RUnlock()
		if !ok || !f.CanQuarantine {
			apiError(w, 404, errors.New("unknown finding"))
			return
		}
		st, err := os.Lstat(f.Path)
		if err != nil {
			apiError(w, 400, err)
			return
		}
		if !st.Mode().IsRegular() || isReparse(f.Path) {
			apiError(w, 400, errors.New("file is not a regular file"))
			return
		}
		if st.Size() > 1024*1024*1024 {
			apiError(w, 400, errors.New("file exceeds 1 GiB; hash calculation disabled for performance"))
			return
		}
		hash, err := fileSHA256(f.Path)
		if err != nil {
			apiError(w, 500, err)
			return
		}
		sendJSON(w, map[string]any{"sha256": hash})
	})
	mux.HandleFunc("/api/quarantine", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		var req struct {
			IDs     []string
			Confirm bool
		}
		if err := readJSON(r, &req); err != nil {
			apiError(w, 400, err)
			return
		}
		if !req.Confirm || len(req.IDs) == 0 || len(req.IDs) > 100 {
			apiError(w, 400, errors.New("explicit approval and 1–100 selected files required"))
			return
		}
		s.app.mu.Lock()
		if s.app.status.Active || s.app.busy {
			s.app.mu.Unlock()
			apiError(w, 409, errors.New("wait until scan or another file operation completes"))
			return
		}
		s.app.busy = true
		fs := []Finding{}
		for _, id := range req.IDs {
			f, ok := s.app.findings[id]
			if !ok || !f.CanQuarantine {
				s.app.busy = false
				s.app.mu.Unlock()
				apiError(w, 400, errors.New("invalid or inaccessible selected file"))
				return
			}
			fs = append(fs, f)
		}
		s.app.mu.Unlock()
		defer func() { s.app.mu.Lock(); s.app.busy = false; s.app.mu.Unlock() }()
		results := []map[string]string{}
		for _, f := range fs {
			_, err := s.app.quarantine.quarantine(f)
			entry := map[string]string{"id": f.ID, "name": f.Name, "status": "ok"}
			if err != nil {
				entry["status"] = "error"
				entry["error"] = err.Error()
			} else {
				s.app.mu.Lock()
				f.CanQuarantine = false
				f.Reasons = append(f.Reasons, "Moved to SentinelGuard quarantine")
				s.app.findings[f.ID] = f
				s.app.mu.Unlock()
			}
			results = append(results, entry)
		}
		sendJSON(w, map[string]any{"results": results})
	})
	mux.HandleFunc("/api/vault", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.app.quarantine.list()
		if err != nil {
			apiError(w, 500, err)
			return
		}
		sendJSON(w, map[string]any{"items": items})
	})
	mux.HandleFunc("/api/vault-action", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		var req struct {
			ID, Action string
			Confirm    bool
		}
		if err := readJSON(r, &req); err != nil {
			apiError(w, 400, err)
			return
		}
		if !req.Confirm {
			apiError(w, 400, errors.New("explicit approval required"))
			return
		}
		s.app.mu.Lock()
		if s.app.status.Active || s.app.busy {
			s.app.mu.Unlock()
			apiError(w, 409, errors.New("finish scanning first"))
			return
		}
		s.app.busy = true
		s.app.mu.Unlock()
		defer func() { s.app.mu.Lock(); s.app.busy = false; s.app.mu.Unlock() }()
		var err error
		switch req.Action {
		case "restore":
			err = s.app.quarantine.restore(req.ID)
		case "delete":
			err = s.app.quarantine.permanentlyDelete(req.ID)
		default:
			err = errors.New("invalid action")
		}
		if err != nil {
			apiError(w, 400, err)
			return
		}
		sendJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/security", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		if err := openWindowsSecurity(); err != nil {
			apiError(w, 500, err)
			return
		}
		sendJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		st, fs := s.app.snapshot()
		skippedPaths := s.app.skippedSnapshot()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="SentinelGuard_v4.1_Report.json"`)
		report:=map[string]any{"product": "SentinelGuard", "version": "4.1", "exportedAt": time.Now(), "status": st, "findings": fs, "skippedPaths": skippedPaths, "notice": "These findings may be false positives. Defender scans are separate from heuristic scans."}
        if s.active!=nil {report["liveProtection"]=s.active.snapshot()}
        if r.URL.Query().Get("redacted")=="1"{
            safe,err:=redactExport(report)
            if err!=nil{apiError(w,500,err);return}
            w.Header().Set("Content-Disposition",`attachment; filename="SentinelGuard_v4.2_Redacted_Report.json"`)
            sendJSON(w,safe)
            return
        }
        sendJSON(w,report)
	})
	mux.HandleFunc("/api/exit", func(w http.ResponseWriter, r *http.Request) {
		if !requirePost(w, r) {
			return
		}
		s.app.mu.RLock()
		busy := s.app.busy
		s.app.mu.RUnlock()
		if busy {
			apiError(w, 409, errors.New("wait for file operations to finish before exiting"))
			return
		}
		s.app.stop()
		sendJSON(w, map[string]any{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); os.Exit(0) }()
	})
	registerActiveRoutes(mux,s)
    registerLaunchRoutes(mux,s)
	return s.secure(mux)
}

func main() {
	initDiagnostics()
	vault, err := openVault()
	if err != nil {
		reportStartupError("Could not create quarantine folder: " + err.Error())
		log.Fatal(err)
	}
	rnd := make([]byte, 32)
	if _, err = rand.Read(rnd); err != nil {
		reportStartupError(err.Error())
		log.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(rnd)
	listener, err := net.Listen("tcp4", "127.0.0.1:17654")
	if err != nil {
		reportStartupError("Cannot bind SentinelGuard private loopback port 17654; close other instances. "+err.Error())
		log.Fatal(err)
	}
	server := &Server{app: newApp(vault), token: token, address: listener.Addr().String()}
    if edition=="integrated" || edition=="active" {
        server.active=newActiveMonitor(vault)
        var pairErr error
        server.extensionToken,server.pairPersisted,pairErr=loadProtectedPairingToken()
        if pairErr!=nil {
            log.Printf("Browser pairing is session-only: %v",pairErr)
            browserSecret:=make([]byte,32)
            if _,err:=rand.Read(browserSecret);err!=nil{log.Fatal(err)}
            server.extensionToken=base64.RawURLEncoding.EncodeToString(browserSecret)
        }
        server.active.start()
    }
	url := "http://" + server.address + "/app/?token=" + token
	httpSrv := &http.Server{Handler: server.routes(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 35 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		if err := httpSrv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			reportStartupError(err.Error())
			log.Print(err)
		}
	}()
	// The native desktop window and its scanner backend live in the same
    // executable. The explicit CI headless switch never enables protection.
    if os.Getenv("SENTINELGUARD_TEST_NO_GUI")=="1" {
        select {}
    }
    if err:=openDesktop(url);err!=nil {
        reportStartupError("Could not open SentinelGuard desktop window: "+err.Error())
        log.Printf("Could not create native window: %v",err)
    }
    if server.active!=nil {_=server.active.setEnabled(false)}
    server.app.stop()
    _=httpSrv.Close()
}
