package main

import (
  "encoding/json"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/base64"
  "encoding/hex"
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
  original:=edition;edition="integrated";defer func(){edition=original}()
  monitor:=newActiveMonitor(nil)
  // Synthetic 32-byte secret encoded as URL-safe base64, never transmitted.
  secret:=[]byte("01234567890123456789012345678901")
  token:=base64.RawURLEncoding.EncodeToString(secret)
  server:=&Server{app:newApp(nil),active:monitor,token:"scanner-admin-secret",
      extensionToken:token,address:"127.0.0.1:18885"}
  const origin="moz-extension://11111111-2222-3333-4444-555555555555"
  nonce:=base64.RawURLEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"))
  req:=httptest.NewRequest(http.MethodPost,"http://127.0.0.1:18885/api/active/extension-challenge",
    strings.NewReader(`{"nonce":"`+nonce+`"}`))
  req.RemoteAddr="127.0.0.1:47000"
  req.Header.Set("Origin",origin)
  result:=httptest.NewRecorder()
  server.routes().ServeHTTP(result,req)
  if result.Code!=200{t.Fatalf("HMAC challenge failed %d: %s",result.Code,result.Body.String())}
  var output struct{Nonce string;Edition string;Proof string;Enabled bool}
  if err:=json.Unmarshal(result.Body.Bytes(),&output);err!=nil{t.Fatal(err)}
  if output.Enabled||output.Edition!="SentinelGuard 4.2"||output.Nonce!=nonce{t.Fatalf("invalid status %v",output)}
  mac:=hmac.New(sha256.New,secret)
  _,_=mac.Write([]byte("SentinelGuard4.2|"+nonce+"|0|SentinelGuard 4.2"))
  if output.Proof!=hex.EncodeToString(mac.Sum(nil)){t.Fatal("response proof did not verify")}
  oldBearer:=activeRequest(server,http.MethodGet,"/api/active/extension-status",token,origin)
  if oldBearer.Code!=403{t.Fatalf("browser must not use legacy bearer status endpoint: %d",oldBearer.Code)}
  bad:=activeRequest(server,http.MethodPost,"/api/active/toggle",token,origin)
  if bad.Code!=403{t.Fatalf("read-only token could toggle protection: %d",bad.Code)}
  admin:=activeRequest(server,http.MethodGet,"/api/active/browser-pair","scanner-admin-secret","")
  if admin.Code!=200||!strings.Contains(admin.Body.String(),token){t.Fatal("pairing endpoint unavailable to admin")}
}
func TestStandardEditionHasNoActiveAPI(t *testing.T){
  original:=edition;edition="standard";defer func(){edition=original}()
  server:=&Server{app:newApp(nil),token:"test-admin",address:"127.0.0.1:18885"}
  res:=activeRequest(server,http.MethodGet,"/api/active/status","test-admin","")
  if res.Code!=404{t.Fatalf("active edition endpoint present in standard edition: %d",res.Code)}
}
