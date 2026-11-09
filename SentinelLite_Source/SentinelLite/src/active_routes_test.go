package main

import (
  "encoding/json"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/base64"
  "bytes"
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
  // Security contract intentionally changed in 4.2: the extension no
  // longer sends its raw bearer secret on each localhost status request.
  key:=bytes.Repeat([]byte{7},32)
  pair:=base64.RawURLEncoding.EncodeToString(key)
  server:=&Server{app:newApp(nil),active:monitor,token:"scanner-admin-secret",
      extensionToken:pair,address:"127.0.0.1:18885"}
  const origin="moz-extension://11111111-2222-3333-4444-555555555555"
  const nonce="abcdefghijklmnopqrstuvwxyzABCDEF0123456789_"
  path:="/api/active/extension-challenge?nonce="+nonce
  good:=activeRequest(server,http.MethodGet,path,"",origin)
  if good.Code!=200 {t.Fatalf("extension challenge failed: %d %s",good.Code,good.Body.String())}
  var status struct{Enabled bool;Edition string;Nonce string;MAC string}
  if err:=json.Unmarshal(good.Body.Bytes(),&status);err!=nil{t.Fatal(err)}
  if status.Enabled||status.Edition!="SentinelGuard 4.2"||status.Nonce!=nonce{
    t.Fatalf("invalid signed status: %+v",status)
  }
  mac:=hmac.New(sha256.New,key)
  mac.Write([]byte("SG4.2|"+nonce+"|false|SentinelGuard 4.2"))
  expected:=base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
  if !hmac.Equal([]byte(status.MAC),[]byte(expected)){t.Fatal("challenge HMAC cannot be verified")}
  bad:=activeRequest(server,http.MethodPost,"/api/active/toggle",pair,origin)
  if bad.Code!=403{t.Fatalf("pairing secret used to toggle protection: HTTP %d",bad.Code)}
  admin:=activeRequest(server,http.MethodGet,"/api/active/browser-pair","scanner-admin-secret","")
  if admin.Code!=200 || !strings.Contains(admin.Body.String(),pair){t.Fatalf("admin pairing endpoint failed: %s",admin.Body.String())}
  oldAPI:=activeRequest(server,http.MethodGet,"/api/active/extension-status",pair,origin)
  if oldAPI.Code!=403{t.Fatalf("obsolete bearer-token endpoint still accessible: HTTP %d",oldAPI.Code)}
  noNonce:=activeRequest(server,http.MethodGet,"/api/active/extension-challenge","","")
  if noNonce.Code!=403{t.Fatalf("challenge accessible without nonce: %d",noNonce.Code)}
}
func TestStandardEditionHasNoActiveAPI(t *testing.T){
  original:=edition;edition="standard";defer func(){edition=original}()
  server:=&Server{app:newApp(nil),token:"test-admin",address:"127.0.0.1:18885"}
  res:=activeRequest(server,http.MethodGet,"/api/active/status","test-admin","")
  if res.Code!=404{t.Fatalf("active edition endpoint present in standard edition: %d",res.Code)}
}
