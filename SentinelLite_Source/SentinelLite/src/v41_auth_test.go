package main

import(
    "net/http"
    "net/http/httptest"
    "encoding/json"
    "testing"
)
func TestV41LaunchOptInStateExposedByAuthenticatedAPI(t *testing.T){
    monitor:=newActiveMonitor(nil)
    server:=&Server{app:newApp(nil),active:monitor,token:"full-access",extensionToken:"read-only",address:"127.0.0.1:17654"}
    req:=httptest.NewRequest(http.MethodPost,"http://127.0.0.1:17654/api/active/launch-toggle",nil)
    req.RemoteAddr="127.0.0.1:24567";req.Header.Set("X-Sentinel-Token","read-only")
    out:=httptest.NewRecorder();server.routes().ServeHTTP(out,req)
    if out.Code!=http.StatusForbidden{t.Fatalf("read-only extension token controlled executable approval: %d",out.Code)}
    statusReq:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:17654/api/active/status",nil)
    statusReq.RemoteAddr="127.0.0.1:24567";statusReq.Header.Set("X-Sentinel-Token","full-access")
    out=httptest.NewRecorder();server.routes().ServeHTTP(out,statusReq)
    if out.Code!=200{t.Fatalf("status endpoint code %d",out.Code)}
    var st struct{LaunchReviewEnabled bool `json:"launchReviewEnabled"`}
    if err:=json.Unmarshal(out.Body.Bytes(),&st);err!=nil{t.Fatal(err)}
    if st.LaunchReviewEnabled{t.Fatal("launch review was not OFF by default")}
}
