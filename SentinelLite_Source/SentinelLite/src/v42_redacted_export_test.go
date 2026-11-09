package main
import(
 "encoding/json"
 "strings"
 "testing"
)
func TestV42RedactedReportsPreserveEvidenceWithoutLeakingPaths(t *testing.T){
 source:=map[string]any{
  "status":map[string]any{"files":130,"current":`C:\Users\PrivateUser\Downloads\secret.exe`,
    "watchedFolders":[]string{`C:\Users\PrivateUser\Downloads`}},
  "findings":[]map[string]any{{"path":`C:\Users\PrivateUser\Downloads\secret.exe`,"name":"secret.exe",
    "score":88,"reasons":[]string{`Threat in C:\Users\PrivateUser\Downloads\secret.exe`}}},
  "skippedPaths":[]map[string]any{{"path":`C:\Users\PrivateUser\Documents\notes.txt`,"reason":"Access denied"}},
 }
 v,err:=v42RedactReport(source);if err!=nil{t.Fatal(err)}
 encoded,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
 text:=string(encoded)
 if strings.Contains(text,"PrivateUser")||strings.Contains(text,"secret.exe")||strings.Contains(text,"notes.txt")||
    strings.Contains(text,`C:\Users`){t.Fatalf("private identifier leaked into redacted export: %s",text)}
 if !strings.Contains(text,"redacted-")||!strings.Contains(text,`"score":88`)||!strings.Contains(text,`"files":130`){
    t.Fatalf("redacted export discarded score/counter evidence: %s",text)}
 v2,err:=v42RedactReport(source);if err!=nil{t.Fatal(err)}
 encoded2,_:=json.Marshal(v2)
 if string(encoded2)==text{t.Fatal("redaction hashes should rotate between exports")}
 full,_:=json.Marshal(source)
 if !strings.Contains(string(full),"PrivateUser"){t.Fatal("full user-selected export was inadvertently mutated")}
}

func TestSecurityRedactsNewWebViewProcessMetadataWithSpaces(t *testing.T){
    raw:=map[string]any{
        "status":map[string]any{
            "childProcessesObserved":1,
            "childProcessesExpected":1,
            "childProcessesUnexpected":0,
            "childProcessImages":[]string{"msedgewebview2.exe"},
            "childProcessEntries":[]map[string]any{{
                "pid":2232,"parentPid":7924,"image":"msedgewebview2.exe",
                "executablePath":`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\155.0.4321.44\msedgewebview2.exe`,
                "classification":"expected-webview2",
                "signatureStatus":"Trusted embedded signature (offline; revocation not checked)",
            }},
        },
    }
    v,err:=v42RedactReport(raw);if err!=nil{t.Fatal(err)}
    encoded,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
    text:=string(encoded)
    for _,secret:=range []string{"Program Files","EdgeWebView","Application","msedgewebview2.exe",`C:\`} {
        if strings.Contains(text,secret){t.Fatalf("redacted child metadata leaked %q: %s",secret,text)}
    }
    if !strings.Contains(text,`"childProcessesObserved":1`) ||
       !strings.Contains(text,`"classification":"expected-webview2"`){
        t.Fatalf("privacy redaction erased evidence categorization: %s",text)
    }
}
