package main

import (
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"
)

// A request panic must fail with HTTP 500 rather than abruptly dropping
// a browser fetch. This does not replace process-wide panic investigation.
func TestStage12APIExceptionDoesNotDropConnection(t *testing.T) {
    srv:=&Server{app:nil,token:"probe",address:"127.0.0.1:18996"}
    req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:18996/api/snapshot",nil)
    req.RemoteAddr="127.0.0.1:50000"
    req.Header.Set("X-Sentinel-Token","probe")
    rec:=httptest.NewRecorder()
    srv.routes().ServeHTTP(rec,req)
    if rec.Code!=http.StatusInternalServerError {
        t.Fatalf("panic must be handled as HTTP 500, got %d",rec.Code)
    }
}

// Stage 12 performs a small bounded sample on photos and notes; an entire
// large input must not be loaded just to evaluate a weak text-format clue.
func TestStage12LargeBenignFileReadLimits(t *testing.T) {
    for _,caseName:=range []string{"photo.jpg","long-notes.txt"} {
        path:=filepath.Join(t.TempDir(),caseName)
        f,err:=os.Create(path);if err!=nil{t.Fatal(err)}
        payload:=make([]byte,4096)
        if caseName=="photo.jpg"{copy(payload,[]byte{0xff,0xd8,0xff,0xdb})}
        if _,err=f.Write(payload);err!=nil{t.Fatal(err)}
        if err=f.Truncate(16*1024*1024);err!=nil{t.Fatal(err)}
        if err=f.Close();err!=nil{t.Fatal(err)}
        st,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
        if finding:=inspectFile(path,st);finding!=nil {
            t.Fatalf("unexpected detection on large benign %s: %+v",caseName,finding)
        }
    }
}
