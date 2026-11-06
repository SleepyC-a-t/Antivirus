package main

import(
    "errors"
    "net/http"
    "os"
    "time"
)
func registerActiveRoutes(mux *http.ServeMux,s *Server){
    // Standard edition exposes no active-control routes.
    if s.active==nil {return}
    mux.HandleFunc("/api/active/status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        sendJSON(w,s.active.snapshot())
    })
    mux.HandleFunc("/api/active/extension-status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        snap:=s.active.snapshot()
        sendJSON(w,map[string]any{"enabled":snap.Enabled,"edition":"SentinelGuard Active","paired":true,"browserProtectionNote":"The extension blocks exact addresses listed by the opted-in phishing feed; it cannot examine web page content or all HTTPS traffic."})
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
        w.Header().Set("Content-Disposition",`attachment; filename="SentinelGuard_Active_Report.json"`)
        sendJSON(w,map[string]any{"product":"SentinelGuard Active","version":"0.1-preview","exportedAt":time.Now(),"status":s.active.snapshot(),"privacy":"Contains absolute file paths, scan detection reasons and local timestamps. No internet history, passwords, cookies or uploaded file contents."})
    })
}
var _ = errors.New
var _ = os.ErrNotExist
