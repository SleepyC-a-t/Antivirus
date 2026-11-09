package main

import(
    "fmt"
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
        sendJSON(w,map[string]any{"pairing":"http://"+s.address+"/api/active/extension-challenge?pair="+pair,"persistent":persisted})
    })
    mux.HandleFunc("/api/active/browser-revoke",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        if err:=s.updatePairToken();err!=nil{apiError(w,http.StatusInternalServerError,err);return}
        sendJSON(w,map[string]any{"revoked":true,"note":"Previous extension pairing is now invalid."})
    })
    mux.HandleFunc("/api/active/extension-challenge",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        nonce:=r.URL.Query().Get("nonce")
        if !browserChallengeNonce.MatchString(nonce){apiError(w,400,fmt.Errorf("invalid challenge nonce"));return}
        snap:=s.active.snapshot()
        mac:=s.browserChallengeMAC(nonce,snap.Enabled)
        if mac==""{apiError(w,503,fmt.Errorf("browser credential unavailable"));return}
        sendJSON(w,map[string]any{"enabled":snap.Enabled,"edition":appEdition,"nonce":nonce,"mac":mac})
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
        w.Header().Set("Content-Disposition",`attachment; filename="SentinelGuard_v4.2_Live_Report.json"`)
        report:=map[string]any{"product":appEdition,"version":appVersion,"exportedAt":time.Now(),"status":s.active.snapshot(),"privacy":"Contains absolute file paths, scan detection reasons and local timestamps. No internet history, passwords, cookies or uploaded file contents."}
        if r.URL.Query().Get("redact")=="1"{
            masked,err:=v42RedactReport(report)
            if err!=nil{apiError(w,500,err);return}
            sendJSON(w,masked);return
        }
        sendJSON(w,report)
    })
}
