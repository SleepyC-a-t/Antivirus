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
 if data.Version!="4.1"||data.Status.LaunchReviews!=1||data.Status.LaunchDenied!=1||len(data.Status.Events)!=2{
  t.Fatalf("launch events missing from JSON report: %+v",data)
 }
}
