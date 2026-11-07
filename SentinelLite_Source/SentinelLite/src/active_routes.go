package main

import(
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "net/http"
    "strings"
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
    mux.HandleFunc("/api/active/extension-challenge",func(w http.ResponseWriter,r *http.Request){
        if !requirePost(w,r){return}
        var req struct{Nonce string `json:"nonce"`}
        if err:=readJSON(r,&req);err!=nil{apiError(w,400,err);return}
        rawNonce,err:=base64.RawURLEncoding.DecodeString(req.Nonce)
        if err!=nil||len(rawNonce)!=32||len(req.Nonce)!=43 {
            apiError(w,400,errors.New("invalid 32-byte challenge nonce"));return
        }
        if strings.ContainsAny(req.Nonce,"=+"){apiError(w,400,errors.New("invalid nonce encoding"));return}
        token,_:=s.pairSnapshot()
        key,err:=base64.RawURLEncoding.DecodeString(token)
        if err!=nil||len(key)!=32{apiError(w,503,errors.New("browser pairing is not available"));return}
        enabled:=s.active.snapshot().Enabled
        state:="0"
        if enabled{state="1"}
        edition:="SentinelGuard 4.2"
        message:="SentinelGuard4.2|"+req.Nonce+"|"+state+"|"+edition
        mac:=hmac.New(sha256.New,key)
        _,_=mac.Write([]byte(message))
        sendJSON(w,map[string]any{"edition":edition,"enabled":enabled,"nonce":req.Nonce,"proof":hex.EncodeToString(mac.Sum(nil))})
    })
    mux.HandleFunc("/api/active/extension-status",func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodGet{http.Error(w,"GET required",405);return}
        snap:=s.active.snapshot()
        sendJSON(w,map[string]any{"enabled":snap.Enabled,"edition":"SentinelGuard 4.2","paired":true,"browserProtectionNote":"The extension blocks exact addresses listed by the opted-in phishing feed; it cannot examine web page content or all HTTPS traffic."})
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
        report:=map[string]any{"product":"SentinelGuard 4.2","version":"4.2","exportedAt":time.Now(),"status":s.active.snapshot(),"privacy":"Contains absolute file paths, scan detection reasons, SHA-256 and local timestamps; redacted=1 omits identifying paths and hashes. No internet history, passwords, cookies or uploaded file contents."}
        if r.URL.Query().Get("redacted")=="1"{
           safe,err:=redactExport(report)
           if err!=nil{apiError(w,500,err);return}
           w.Header().Set("Content-Disposition",`attachment; filename="SentinelGuard_v4.2_Redacted_Live_Report.json"`)
           sendJSON(w,safe)
           return
        }
        sendJSON(w,report)
    })
}
