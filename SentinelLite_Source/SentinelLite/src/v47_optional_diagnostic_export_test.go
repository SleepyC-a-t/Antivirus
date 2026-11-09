package main

import (
  "encoding/json"
  "net/http"
  "net/http/httptest"
  "os"
  "path/filepath"
  "strings"
  "testing"
)

func diagnosticTestServer(t *testing.T)(*Server,*App,string){
  t.Helper()
  p:=filepath.Join(t.TempDir(),"inert-secret-example.exe")
  if err:=os.WriteFile(p,[]byte("INERT_TEST_DOCUMENT__PRIVATE_STRING_NOT_FOR_EXPORT"),0600);err!=nil{t.Fatal(err)}
  info,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  a:=newApp(nil)
  a.add(Finding{Path:p,Name:filepath.Base(p),Score:51,Severity:"Review",
    Source:"Heuristics",Reasons:[]string{"Executable in a temporary folder","PE import triad is advisory until corroborated"},
    Size:info.Size(),Modified:info.ModTime(),CanQuarantine:true,ReviewSHA256:strings.Repeat("f",64)})
  return &Server{app:a,token:"test-token",address:"127.0.0.1:19001"},a,p
}

func diagnosticReport(t *testing.T,srv *Server,query string) map[string]any {
  t.Helper()
  req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:19001/api/report"+query,nil)
  req.RemoteAddr="127.0.0.1:12345"
  req.Header.Set("X-Sentinel-Token","test-token")
  rec:=httptest.NewRecorder()
  srv.routes().ServeHTTP(rec,req)
  if rec.Code!=200{t.Fatalf("status %d: %s",rec.Code,rec.Body.String())}
  var report map[string]any
  if err:=json.Unmarshal(rec.Body.Bytes(),&report);err!=nil{t.Fatal(err)}
  return report
}

func TestV47DefaultReportDoesNotCollectExtraDiagnostics(t *testing.T){
  srv,_,_:=diagnosticTestServer(t)
  r:=diagnosticReport(t,srv,"")
  if r["diagnosticsIncluded"]!=false{t.Fatalf("diagnostics not OFF by default: %+v",r)}
  if _,ok:=r["diagnosticData"];ok{t.Fatal("default report unexpectedly includes diagnostic metadata")}
  if _,ok:=r["diagnosticPrivacyNotice"];ok{t.Fatal("default export should not append extra diagnostic notice")}
}

func TestV47ExplicitDiagnosticsIncludeUsefulMetadataWithoutContent(t *testing.T){
  srv,_,p:=diagnosticTestServer(t)
  report:=diagnosticReport(t,srv,"?diagnostics=1")
  if report["diagnosticsIncluded"]!=true||report["diagnosticSchemaVersion"]!=float64(1){t.Fatal("optional diagnostic schema missing")}
  items,ok:=report["diagnosticData"].([]any)
  if !ok||len(items)!=1{t.Fatalf("wrong diagnostic list: %#v",report["diagnosticData"])}
  entry:=items[0].(map[string]any)
  if entry["status"]!="collected" || entry["extension"]!=".exe" ||
     entry["sha256AtScan"]!=strings.Repeat("f",64) ||
     entry["fileType"]!="Unrecognized/other"{
       t.Fatalf("metadata unexpectedly missing: %#v",entry)
  }
  indicators:=entry["nameOrLocationIndicators"].([]any)
  if len(indicators)!=1||indicators[0]!="temporary-location rule"{t.Fatalf("missing rule context: %#v",indicators)}
  encoded,_:=json.Marshal(report)
  if strings.Contains(string(encoded),"INERT_TEST_DOCUMENT__PRIVATE_STRING_NOT_FOR_EXPORT"){
    t.Fatal("diagnostic export leaked actual file bytes")
  }
  if strings.Contains(string(encoded),`"diagnosticData":[{"path"`){
    t.Fatal("diagnostic entry should not duplicate absolute paths")
  }
  if _,err:=os.Stat(p);err!=nil{t.Fatal("export changed the original file")}
}

func TestV47RedactedOptionalDiagnosticsMaskHashesAndSkipErrorPaths(t *testing.T){
  srv,app,_:=diagnosticTestServer(t)
  app.recordSkip(`C:\Program Files (x86)\Secret Tool\MyAccount\System SID 0123`,
    `directory listing failed: open C:\Program Files (x86)\Secret Tool\MyAccount\System SID 0123: Access is denied.`)
  report:=diagnosticReport(t,srv,"?diagnostics=1&redact=1")
  encoded,_:=json.Marshal(report)
  text:=string(encoded)
  for _,str:=range []string{"inert-secret-example.exe","Secret Tool","MyAccount","Program Files","INERT_TEST_DOCUMENT",strings.Repeat("f",64)}{
    if strings.Contains(text,str){t.Fatalf("redacted diagnostics leaked %q",str)}
  }
  if !strings.Contains(text,`"sha256AtScan":"[digest redacted]"`) ||
     !strings.Contains(text,`"reason":"directory listing denied"`){
    t.Fatalf("redacted hash or skip errors were not properly masked: %s",text)
  }
}

func TestV47DiagnosticsDoNotOpenFilesChangedAfterScan(t *testing.T){
  srv,_,p:=diagnosticTestServer(t)
  if err:=os.WriteFile(p,[]byte("file changed and is not safe to treat as old scanned evidence"),0600);err!=nil{t.Fatal(err)}
  report:=diagnosticReport(t,srv,"?diagnostics=1")
  entry:=report["diagnosticData"].([]any)[0].(map[string]any)
  if entry["status"]!="changed"{t.Fatalf("file must be marked changed, got %#v",entry)}
  if entry["sha256AtScan"]!=nil || entry["pe"]!=nil{t.Fatalf("diagnostics falsely attribute scan evidence to changed file: %#v",entry)}
}

func TestV47DiagnosticsCapRecordsAndDoNotInspectUnboundedFiles(t *testing.T){
  findings:=make([]Finding,maxExportDiagnostics+11)
  for i:=range findings{
    findings[i]=Finding{ID:"inert-id",Path:filepath.Join(t.TempDir(),"not-there"),Name:"not-there.exe"}
  }
  items,omitted:=collectExportDiagnostics(findings)
  if len(items)!=maxExportDiagnostics||omitted!=11{
    t.Fatalf("diagnostic limit not enforced: got=%d omitted=%d",len(items),omitted)
  }
}
