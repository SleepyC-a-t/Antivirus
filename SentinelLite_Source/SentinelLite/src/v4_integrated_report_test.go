package main

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestV4IntegratedManualAndLiveReport(t *testing.T){
    m:=newActiveMonitor(nil)
    if m.snapshot().Enabled||m.snapshot().AutoQuarantine {t.Fatal("live protection default must be OFF")}
    server:=&Server{
        app:newApp(nil),active:m,token:"dev-token",extensionToken:"extension-token",address:"127.0.0.1:19878",
    }
    req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:19878/api/report",nil)
    req.RemoteAddr="127.0.0.1:37110"
    req.Header.Set("X-Sentinel-Token","dev-token")
    response:=httptest.NewRecorder()
    server.routes().ServeHTTP(response,req)
    if response.Code!=200 {t.Fatalf("report status=%d",response.Code)}
    var got struct {
        Version string `json:"version"`
        LiveProtection struct {
            Enabled bool `json:"enabled"`
            AutoQuarantine bool `json:"autoQuarantine"`
            Inspected int64 `json:"inspected"`
        } `json:"liveProtection"`
    }
    if err:=json.Unmarshal(response.Body.Bytes(),&got);err!=nil{t.Fatal(err)}
    if got.Version!="4.1"||got.LiveProtection.Enabled||got.LiveProtection.AutoQuarantine {
        t.Fatalf("wrong unified report fields: %+v",got)
    }
}
