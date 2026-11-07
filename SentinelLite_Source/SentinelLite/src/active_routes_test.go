package main

import (
  "encoding/json"
  "net/http"
  "net/http/httptest"
  "strings"
  "testing"
)

func activeRequest(server *Server, method,path,token,origin string) *httptest.ResponseRecorder{
  body:=strings.NewReader("{}")
  req:=httptest.NewRequest(method,"http://127.0.0.1:18885"+path,body)
  req.RemoteAddr="127.0.0.1:47000"
  req.Header.Set("X-Sentinel-Token",token)
  if origin!=""{req.Header.Set("Origin",origin)}
  rec:=httptest.NewRecorder()
  server.routes().ServeHTTP(rec,req)
  return rec
}
func TestActiveBrowserPairingIsReadOnly(t *testing.T) {
  original:=edition
  edition="integrated"
  defer func(){edition=original}()
  monitor:=newActiveMonitor(nil)
  server:=&Server{app:newApp(nil),active:monitor,token:"scanner-admin-secret",
      extensionToken:"browser-status-secret",address:"127.0.0.1:18885"}
  const origin="moz-extension://11111111-2222-3333-4444-555555555555"
  good:=activeRequest(server,http.MethodGet,"/api/active/extension-status","browser-status-secret",origin)
  if good.Code!=200 {t.Fatalf("extension status request failed: %d %s",good.Code,good.Body.String())}
  var status struct{Enabled bool}
  if err:=json.Unmarshal(good.Body.Bytes(),&status);err!=nil{t.Fatal(err)}
  if status.Enabled{t.Fatal("active protection should default to OFF")}
  bad:=activeRequest(server,http.MethodPost,"/api/active/toggle","browser-status-secret",origin)
  if bad.Code!=403{t.Fatalf("read-only browser token used to toggle protection: HTTP %d",bad.Code)}
  admin:=activeRequest(server,http.MethodGet,"/api/active/browser-pair","scanner-admin-secret","")
  if admin.Code!=200 || !strings.Contains(admin.Body.String(),"browser-status-secret"){t.Fatalf("admin pairing endpoint failed: %s",admin.Body.String())}
  noToken:=activeRequest(server,http.MethodGet,"/api/active/extension-status","","")
  if noToken.Code!=403 {t.Fatalf("extension status exposed without token, code=%d",noToken.Code)}
}
func TestStandardEditionHasNoActiveAPI(t *testing.T){
  original:=edition;edition="standard";defer func(){edition=original}()
  server:=&Server{app:newApp(nil),token:"test-admin",address:"127.0.0.1:18885"}
  res:=activeRequest(server,http.MethodGet,"/api/active/status","test-admin","")
  if res.Code!=404{t.Fatalf("active edition endpoint present in standard edition: %d",res.Code)}
}
