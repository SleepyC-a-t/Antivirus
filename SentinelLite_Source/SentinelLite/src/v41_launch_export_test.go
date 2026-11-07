package main
import(
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
)
func TestV41LaunchAuditIncludedInActiveExport(t *testing.T){
 m:=newActiveMonitor(nil)
 m.recordLaunch(`C:\Temp\harmless.exe`,"launch-reviewed","read-only review",63)
 m.recordLaunch(`C:\Temp\harmless.exe`,"launch-cancelled","user declined",63)
 srv:=&Server{app:newApp(nil),active:m,token:"test-admin",address:"127.0.0.1:17654"}
 req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:17654/api/active/report",nil)
 req.RemoteAddr="127.0.0.1:15432"
 req.Header.Set("X-Sentinel-Token","test-admin")
 out:=httptest.NewRecorder();srv.routes().ServeHTTP(out,req)
 if out.Code!=200{t.Fatalf("export status=%d",out.Code)}
 var data struct{
  Version string `json:"version"`
  Status struct{
   LaunchReviews int64 `json:"launchReviews"`
   LaunchDenied int64 `json:"launchDenied"`
   Events []ActiveEvent `json:"events"`
  } `json:"status"`
 }
 if err:=json.Unmarshal(out.Body.Bytes(),&data);err!=nil{t.Fatal(err)}
 if data.Version!="4.2"||data.Status.LaunchReviews!=1||data.Status.LaunchDenied!=1||len(data.Status.Events)!=2{
  t.Fatalf("launch events missing from JSON report: %+v",data)
 }
}

func TestV41LaunchAuditSeparateFromDownloadHistory(t *testing.T){
 m:=newActiveMonitor(nil)
 m.recordLaunch("example.exe","launch-reviewed","test",65)
 m.recordLaunch("example.exe","launch-cancelled","test",65)
 for i:=0;i<350;i++{
  m.mu.Lock()
  m.appendEventLocked(ActiveEvent{Action:"inspected-clean"})
  m.mu.Unlock()
 }
 st:=m.snapshot()
 if len(st.LaunchEvents)!=2{t.Fatalf("launch approvals lost in download history: %+v",st.LaunchEvents)}
 if st.LaunchEvents[1].Action!="launch-cancelled"{t.Fatal("last launch decision absent")}
 for i:=0;i<600;i++{m.recordLaunch("sample.exe","launch-cancelled","synthetic stress",0)}
 st=m.snapshot()
 if len(st.LaunchEvents)!=512||st.LaunchLogOmitted!=90{
  t.Fatalf("launch ring buffer capacity accounting failed: len=%d omitted=%d",len(st.LaunchEvents),st.LaunchLogOmitted)
 }
 m.clearHistory()
 st=m.snapshot()
 if len(st.LaunchEvents)!=0||st.LaunchLogOmitted!=0{t.Fatal("clear history did not clear launch audit")}
}
