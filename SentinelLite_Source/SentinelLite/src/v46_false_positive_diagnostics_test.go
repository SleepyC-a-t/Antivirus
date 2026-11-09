package main

import(
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestV46RuleFamilySummaryOmitsPrivateFilenames(t *testing.T){
    findings:=[]Finding{
        {Path:`C:\Users\PrivateUser\Documents\demo.pdf`,Name:"demo.pdf",Score:50,
         Reasons:[]string{"PDF has document-open and JavaScript action dictionaries (limited structural inspection, not proof of exploit)"}},
        {Path:`C:\Users\PrivateUser\Documents\more.pdf`,Name:"more.pdf",Score:78,
         Reasons:[]string{"PDF has a launch-action dictionary referencing an executable or script"}},
        {Path:`C:\Users\PrivateUser\AppData\Local\archive.zip`,Name:"archive.zip",Score:65,
         Reasons:[]string{"Archive entry private-binary.exe: suspicious script command",
                          "Archive entry private-binary.exe: another reason"}},
    }
    summary:=summarizeFindingReasons(findings)
    raw,err:=json.Marshal(summary);if err!=nil{t.Fatal(err)}
    text:=string(raw)
    if strings.Contains(text,"PrivateUser")||strings.Contains(text,"private-binary")||
       strings.Contains(text,"demo.pdf")||strings.Contains(text,`C:\`){
        t.Fatalf("aggregate rules leaked user-specific paths/names: %s",text)
    }
    if len(summary)!=2||summary[0].RuleFamily!="PDF action or structure"||summary[0].Findings!=2||
      summary[0].HighestScore!=78 ||summary[1].RuleFamily!="Archive content or filename" ||summary[1].Findings!=1{
        t.Fatalf("rule summaries are not correctly de-duplicated and sorted: %+v",summary)
    }
}

func TestV46ManualScanReportIsDistinctFromLiveReport(t *testing.T){
    app:=newApp(nil)
    app.add(Finding{Path:filepath.Join(t.TempDir(),"review.pdf"),Name:"review.pdf",Score:52,
        Severity:"Review",Reasons:[]string{"PDF has a launch-action dictionary referencing an executable or script"}})
    srv:=&Server{app:app,token:"safe-test-token",address:"127.0.0.1:17654"}
    req:=httptest.NewRequest(http.MethodGet,"http://127.0.0.1:17654/api/report?redact=1",nil)
    req.RemoteAddr="127.0.0.1:10234"
    req.Header.Set("X-Sentinel-Token","safe-test-token")
    rec:=httptest.NewRecorder()
    srv.routes().ServeHTTP(rec,req)
    if rec.Code!=http.StatusOK{t.Fatalf("manual scan report status=%d body=%s",rec.Code,rec.Body.String())}
    var report struct{
        Kind string `json:"reportKind"`
        Findings []Finding `json:"findings"`
        RuleSummary []FindingReasonSummary `json:"findingReasonsSummary"`
        Redacted bool `json:"redacted"`
    }
    if err:=json.Unmarshal(rec.Body.Bytes(),&report);err!=nil{t.Fatal(err)}
    if report.Kind!="manualScanFindings"||!report.Redacted||len(report.Findings)!=1||len(report.RuleSummary)!=1{
        t.Fatalf("wrong or incomplete manual scan export: %+v",report)
    }
    if strings.Contains(rec.Body.String(),"review.pdf"){t.Fatal("redacted report leaked a file name")}
}

func TestV46PDFDocumentationDoesNotTriggerLaunchActions(t *testing.T){
    fixtures:=[]struct{name,content string;alert bool}{
        {"manual.pdf", "%PDF-1.7\n1 0 obj << /Type /Catalog /Title (How /S /Launch and /F (installer.exe) work) >>",false},
        {"text.pdf", "%PDF-1.7\n% << /S /Launch /F (installer.cmd) >>\n1 0 obj << /Type /Catalog >>",false},
        {"genuine-action.pdf","%PDF-1.7\n1 0 obj << /Type /Action /S /Launch /F (installer.exe) >>",true},
    }
    for _,tc:=range fixtures{
        t.Run(tc.name,func(t *testing.T){
            file:=filepath.Join(t.TempDir(),tc.name)
            if err:=os.WriteFile(file,[]byte(tc.content),0600);err!=nil{t.Fatal(err)}
            st,err:=os.Stat(file);if err!=nil{t.Fatal(err)}
            got:=inspectFile(file,st)
            if (got!=nil)!=tc.alert{
                t.Fatalf("PDF structural alert=%v expected=%v details=%+v",got!=nil,tc.alert,got)
            }
        })
    }
}
