package main

import (
    "context"
    "encoding/json"
    "errors"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// Tests simulate the Windows dialog result without showing an interactive UI
// in CI. Native COM initialization is separately verified by the Windows build.
func TestCustomFolderPickerEndpoint(t *testing.T) {
    parent := t.TempDir()
    nested := filepath.Join(parent, "child")
    if err := os.MkdirAll(nested, 0700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(nested,"sample.txt"), []byte("inert"), 0600); err!=nil {t.Fatal(err)}
    choose := func(path string, chooseErr error) *httptest.ResponseRecorder {
        srv:=&Server{app:newApp(nil),token:"test-token",address:"127.0.0.1:19055",
            folderPicker:func()(string,error){return path,chooseErr}}
        req:=httptest.NewRequest(http.MethodPost,"http://127.0.0.1:19055/api/choose-folder",nil)
        req.RemoteAddr="127.0.0.1:51000"
        req.Header.Set("X-Sentinel-Token","test-token")
        rec:=httptest.NewRecorder()
        srv.routes().ServeHTTP(rec,req)
        return rec
    }
    good:=choose(parent,nil)
    if good.Code!=200 {t.Fatalf("folder picker rejected valid directory: %s",good.Body.String())}
    var found struct{ Folder string `json:"folder"`; Cancelled bool `json:"cancelled"` }
    if err:=json.Unmarshal(good.Body.Bytes(),&found);err!=nil{t.Fatal(err)}
    if found.Folder!=parent||found.Cancelled {t.Fatalf("wrong folder selected: %+v",found)}
    count:=0
    skipped,err:=walkNoLinksDetailed(context.Background(),found.Folder,func(string){count++},nil)
    if err!=nil||count!=1||skipped!=0 {t.Fatalf("selection was not recursively enumerable count=%d skipped=%d err=%v",count,skipped,err)}
    cancel:=choose("",errFolderPickerCanceled)
    if cancel.Code!=200||!strings.Contains(cancel.Body.String(),`"cancelled":true`){t.Fatalf("cancelling chooser produced an error: %s",cancel.Body.String())}
    bad:=choose(filepath.Join(nested,"sample.txt"),nil)
    if bad.Code!=http.StatusBadRequest {t.Fatalf("file must be rejected, got %d",bad.Code)}
    failure:=choose("",errors.New("dialog failed"))
    if failure.Code!=http.StatusInternalServerError {t.Fatalf("native dialog error lost: %d",failure.Code)}
}

func TestCustomFolderPickerUI(t *testing.T) {
    html,err:=pages.ReadFile("ui.html")
    if err!=nil{t.Fatal(err)}
    for _,needle:=range []string{
        `id="browseFolder"`,`id="customPath"`,`/api/choose-folder`,
        `Choose folder`,`including subfolders`,`$('browseFolder').onclick=chooseFolder`,
    } {
        if !strings.Contains(string(html),needle){t.Errorf("missing native folder picker element: %s",needle)}
    }
}
