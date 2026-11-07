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
