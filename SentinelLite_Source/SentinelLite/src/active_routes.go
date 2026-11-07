package main

import(
    "net/http"
    "errors"
    "time"
)
func registerActiveRoutes(mux *http.ServeMux,s *Server){
    // Standard edition exposes no active-control routes.
    if s.active==nil {return}
    mux.HandleFunc("/api/active/status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/browser-pair",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        // Browser pairings are *read-only*. They cannot toggle scanning,
        // request quarantine, delete files or control the local application.
        sendJSON(w,map[string]any{"pairing":"http://"+s.address+"/api/active/extension-status?pair="+s.getBrowserToken(),"persistent":s.pairingPersistent})
    })
    mux.HandleFunc("/api/active/extension-status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        nonce:=r.Header.Get("X-Sentinel-Nonce")
        if !validBrowserNonce(nonce){apiError(w,400,errors.New("missing or invalid browser challenge"));return}
        snap:=s.active.snapshot()
        sendJSON(w,map[string]any{"enabled":snap.Enabled,"edition":"SentinelGuard 4.1",
            "nonce":nonce,"signature":signBrowserState(s.getBrowserToken(),nonce,snap.Enabled),
            "paired":true,"persistent":s.pairingPersistent,
            "browserProtectionNote":"The extension blocks matched phishing URLs, not all malicious activity."})
    })
    mux.HandleFunc("/api/active/safe-launch-toggle",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{Enabled bool}
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        if err:=s.active.setSafeLaunch(req.Enabled);err!=nil{apiError(w,409,err);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/choose-executable",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        if !s.pickingFolder.CompareAndSwap(false,true){
            apiError(w,409,errors.New("a file picker is already open"));return
        }
        defer s.pickingFolder.Store(false)
        path,err:=chooseExecutableFile()
        if errors.Is(err,errFolderPickerCanceled){sendJSON(w,map[string]any{"cancelled":true});return}
        if err!=nil{apiError(w,500,err);return}
        valid,_,err:=verifyExecutable(path)
        if err!=nil{apiError(w,400,err);return}
        sendJSON(w,map[string]any{"path":valid,"cancelled":false})
    })
    mux.HandleFunc("/api/active/safe-launch",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{Path string}
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        result,err:=s.active.safeLaunchProgram(req.Path,confirmProgramLaunch,nil)
        if err!=nil{apiError(w,400,err);return}
        sendJSON(w,result)
    })
    mux.HandleFunc("/api/active/revoke-browser",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        if !s.pairingPersistent {
            fresh,err:=generateBrowserPairConfig()
            if err!=nil{apiError(w,500,err);return}
            s.setBrowserToken(fresh.Secret)
            sendJSON(w,map[string]any{"revoked":true,"persistent":false})
            return
        }
        cfg,err:=rotateBrowserPairing(s.pairingPath,s.pairingConfig)
        if err!=nil{apiError(w,500,err);return}
        s.pairingConfig=cfg
        s.setBrowserToken(cfg.Secret)
        sendJSON(w,map[string]any{"revoked":true,"persistent":true})
    })
    mux.HandleFunc("/api/active/toggle",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct { Enabled bool }
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        if err:=s.active.setEnabled(req.Enabled);err!=nil{apiError(w,400,err);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/autoblock",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{ Enabled bool }
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        s.active.setAutoQuarantine(req.Enabled)
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/watch",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{ Path string }
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        if err:=s.active.addFolder(req.Path);err!=nil{apiError(w,400,err);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/unwatch",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{ Path string }
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        if err:=s.active.removeFolder(req.Path);err!=nil{apiError(w,400,err);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/clear",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        s.active.clearHistory()
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/report",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        w.Header().Set("Content-Disposition",`attachment; filename="SentinelGuard_v4.1_Live_Report.json"`)
        sendJSON(w,map[string]any{"product":"SentinelGuard 4.1","version":"4.1","exportedAt":time.Now(),"status":s.active.snapshot(),"privacy":"Contains absolute file paths, scan detection reasons and local timestamps. No internet history, passwords, cookies or uploaded file contents."})
    })
}
