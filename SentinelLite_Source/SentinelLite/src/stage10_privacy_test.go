package main

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

// The privacy disclosure must continue to describe the fields that the
// application ACTUALLY exports. This test fails if that contract drifts.
func TestStage10PrivacyDisclosureAndJSONShape(t *testing.T) {
 html,err:=pages.ReadFile("ui.html")
 if err!=nil{t.Fatal(err)}
 for _,phrase:=range []string{
  "Privacy and JSON report contents",
  "Windows account name",
  "Windows account SID",
  "File SHA-256 hashes",
  "does not automatically upload",
  "redact private usernames",
 } {
  if !strings.Contains(string(html),phrase){t.Errorf("missing disclosure: %q",phrase)}
 }
 a:=newApp(nil)
 a.status=Status{Mode:"heuristic:custom",Current:`C:\Users\Test User\Documents`,Started:time.Now()}
 a.add(Finding{Path:`C:\Users\Test User\Documents\private-file.txt`,Name:"private-file.txt",Score:55,Severity:"Review",Source:"Heuristics",Reasons:[]string{"Archive entry personal-file.txt"},Size:100,Modified:time.Now(),CanQuarantine:false,ReviewSHA256:"must-not-be-exported"})
 srv:=&Server{app:a,token:"secret-test-only",address:"127.0.0.1:45678"}
 req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:45678/api/report",nil)
 req.RemoteAddr="127.0.0.1:12345"
 req.Header.Set("X-Sentinel-Token","secret-test-only")
 rec:=httptest.NewRecorder()
 srv.routes().ServeHTTP(rec,req)
 if rec.Code!=http.StatusOK {t.Fatalf("report HTTP status %d: %s",rec.Code,rec.Body.String())}
 if !strings.Contains(rec.Header().Get("Content-Disposition"),"SentinelGuard_v3.2_Report.json"){t.Fatal("export filename not updated")}
 var got struct{
  Product string `json:"product"`
  Version string `json:"version"`
  ExportedAt time.Time `json:"exportedAt"`
  Status struct {Mode string `json:"mode"`; Current string `json:"current"`} `json:"status"`
  Findings []map[string]any `json:"findings"`
 }
 if err:=json.Unmarshal(rec.Body.Bytes(),&got);err!=nil{t.Fatal(err)}
 if got.Product!="SentinelGuard" || got.Version!="3.2" || len(got.Findings)!=1 {t.Fatalf("report metadata incorrect: %+v",got)}
 if got.Status.Current!=`C:\Users\Test User\Documents`{t.Fatal("export paths changed unexpectedly")}
 if got.Findings[0]["path"]!=`C:\Users\Test User\Documents\private-file.txt`{t.Fatal("report must accurately disclose that full paths are present")}
 for _,key:=range []string{"id","path","name","score","severity","source","reasons","size","modified","canQuarantine"} {
  if _,ok:=got.Findings[0][key];!ok{t.Errorf("missing report field %q",key)}
 }
 b:=rec.Body.String()
 for _,secret:=range []string{"must-not-be-exported","secret-test-only","reviewSHA256"} {
  if strings.Contains(b,secret){t.Errorf("sensitive value leaked into report: %q",secret)}
 }
}
