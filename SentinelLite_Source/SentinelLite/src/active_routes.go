package main

import(
    "net/http"
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
        pair,persisted:=s.pairSnapshot()
        sendJSON(w,map[string]any{"pairing":"http://"+s.address+"/api/active/extension-status?pair="+pair,"persistent":persisted})
    })
    mux.HandleFunc("/api/active/browser-revoke",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        if err:=s.updatePairToken();err!=nil{apiError(w,http.StatusInternalServerError,err);return}
        sendJSON(w,map[string]any{"revoked":true,"note":"Previous extension pairing is now invalid."})
    })
    mux.HandleFunc("/api/active/extension-status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        snap:=s.active.snapshot()
        sendJSON(w,map[string]any{"enabled":snap.Enabled,"edition":"SentinelGuard 4.0","paired":true,"browserProtectionNote":"The extension blocks exact addresses listed by the opted-in phishing feed; it cannot examine web page content or all HTTPS traffic."})
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
    mux.HandleFunc("/api/active/launch-toggle",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{Enabled bool}
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        s.active.setLaunchReview(req.Enabled)
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
        sendJSON(w,map[string]any{"product":"SentinelGuard 4.0","version":"4.1","exportedAt":time.Now(),"status":s.active.snapshot(),"privacy":"Contains absolute file paths, scan detection reasons and local timestamps. No internet history, passwords, cookies or uploaded file contents."})
    })
}
